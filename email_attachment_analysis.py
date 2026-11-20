import hashlib
import io
import mimetypes
import re
import tempfile
import zipfile
import zlib
from pathlib import PurePosixPath
from pathlib import Path
from xml.etree import ElementTree

from bs4 import BeautifulSoup
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from file_analysis import analyze_file


MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100
MAX_ARCHIVE_EXPANDED_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_TEXT_CHARACTERS = 100_000
MAX_PDF_PAGES = 50
URL_PATTERN = re.compile(
    r"""(?ix)(?<![\w@])(?:https?://|hxxps?://|www\.)[^\s<>"']+"""
)
EXECUTABLE_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".js", ".jse",
    ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
}
TEXT_EXTENSIONS = {".csv", ".log", ".md", ".text", ".txt"}


def _finding(findings, title, detail, severity="medium"):
    finding = {"title": title, "detail": detail, "severity": severity}
    if finding not in findings:
        findings.append(finding)


def _urls(text):
    results = []
    for match in URL_PATTERN.finditer(text):
        value = match.group(0).rstrip(".,;:!?)]}")
        value = value.replace("&amp;", "&")
        if value.lower().startswith("hxxp"):
            value = "http" + value[4:]
        elif value.lower().startswith("www."):
            value = "https://" + value
        if value not in results:
            results.append(value)
    return results


def _zip_members(data, findings):
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        _finding(findings, "Malformed ZIP archive", "The file has a ZIP signature but its directory is invalid.", "high")
        return "", []

    text_parts = []
    urls = []
    try:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            _finding(findings, "Archive contains too many entries", f"Only the first {MAX_ARCHIVE_MEMBERS} entries are inspected.", "high")
            members = members[:MAX_ARCHIVE_MEMBERS]

        expanded_size = sum(member.file_size for member in members)
        if expanded_size > MAX_ARCHIVE_EXPANDED_BYTES:
            _finding(findings, "Archive expansion limit exceeded", "Contents were not extracted because the declared expanded size exceeds the inspection limit.", "high")
            return "", []

        inspected_text_bytes = 0
        for member in members:
            if member.is_dir():
                continue
            name = member.filename
            path = PurePosixPath(name)
            extension = path.suffix.lower()
            if member.flag_bits & 0x1:
                _finding(findings, "Password-protected archive entry", f"{path.name} is encrypted and could not be inspected.", "medium")
                continue
            if member.file_size > MAX_ARCHIVE_EXPANDED_BYTES:
                _finding(findings, "Oversized archive entry", f"{path.name} exceeds the per-entry inspection limit.", "high")
                continue
            if member.file_size > 1_000_000 and (
                member.compress_size == 0
                or member.file_size / member.compress_size > 1000
            ):
                _finding(findings, "Suspicious compression ratio", f"{path.name} has an unusually high compression ratio.", "high")
                continue
            if extension in EXECUTABLE_EXTENSIONS:
                _finding(findings, "Executable or script inside archive", f"The archive contains {path.name}.", "high")
            if extension in {".zip", ".7z", ".rar"}:
                _finding(findings, "Nested archive", f"The nested archive {path.name} was not recursively unpacked.", "medium")
            if path.name.lower() == "vbaproject.bin":
                _finding(findings, "Office macro project found", "The archive contains a VBA project; its macros were not executed.", "high")
            if extension not in TEXT_EXTENSIONS | {".html", ".htm", ".xhtml"}:
                continue
            if inspected_text_bytes + member.file_size > 4 * 1024 * 1024:
                _finding(findings, "Archive text inspection limit reached", "Remaining text entries were not read.", "medium")
                break
            with archive.open(member) as stream:
                content = stream.read(min(member.file_size, 1_000_000))
            inspected_text_bytes += len(content)
            decoded = content.decode("utf-8", errors="replace")
            if extension in {".html", ".htm", ".xhtml"}:
                soup = BeautifulSoup(decoded, "html.parser")
                for tag in soup.find_all(["a", "form", "iframe", "img", "script"]):
                    for attr in ("href", "src", "action"):
                        target = tag.get(attr)
                        if isinstance(target, str):
                            urls.extend(_urls(target))
                if soup.find("form"):
                    _finding(findings, "HTML form in archive", f"{path.name} contains a form that may collect submitted data.", "high")
                decoded = soup.get_text(" ", strip=True)
            text_parts.append(decoded)
            urls.extend(_urls(decoded))
    except (
        zipfile.BadZipFile,
        OSError,
        EOFError,
        RuntimeError,
        NotImplementedError,
        zlib.error,
    ):
        _finding(
            findings,
            "Archive entry could not be inspected",
            "A compressed archive entry is damaged or uses an unsupported compression method.",
            "medium",
        )
    finally:
        archive.close()

    return "\n".join(text_parts), list(dict.fromkeys(urls))


def _office_zip_text(data, extension, findings):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS or sum(
                member.file_size for member in members
            ) > MAX_ARCHIVE_EXPANDED_BYTES:
                _finding(findings, "Office document exceeds inspection limits", "The document was not expanded because its archive exceeds the safe inspection limits.", "high")
                return ""
            names = {member.filename for member in members}
            if "word/vbaProject.bin" in names or "xl/vbaProject.bin" in names:
                _finding(findings, "Office macro project found", "The document contains a VBA project; its macros were not executed.", "high")
            if extension in {".docm", ".xlsm"}:
                _finding(findings, "Macro-enabled Office file", "This format can contain executable Office macros.", "medium")
            if any(name.endswith(".rels") for name in names):
                for name in names:
                    if not name.endswith(".rels"):
                        continue
                    xml = archive.read(name)
                    if b'TargetMode="External"' in xml or b"TargetMode='External'" in xml:
                        _finding(findings, "External Office relationship", f"{name} references an external resource.", "medium")
            xml_names = (
                [name for name in names if name == "word/document.xml"]
                if extension.startswith(".doc")
                else [
                    name for name in names
                    if name == "xl/sharedStrings.xml"
                    or (name.startswith("xl/worksheets/") and name.endswith(".xml"))
                ]
            )
            text_parts = []
            remaining = MAX_EXTRACTED_TEXT_CHARACTERS
            for name in xml_names:
                xml = archive.read(name)
                root = ElementTree.fromstring(xml)
                for node in root.iter():
                    if node.text and remaining > 0:
                        value = node.text[:remaining]
                        text_parts.append(value)
                        remaining -= len(value)
                if remaining <= 0:
                    break
            return " ".join(text_parts)
    except (
        zipfile.BadZipFile,
        ElementTree.ParseError,
        KeyError,
        OSError,
        RuntimeError,
        NotImplementedError,
        zlib.error,
    ):
        _finding(findings, "Office document could not be parsed", "The Office package is malformed or contains an unsupported structure.", "medium")
        return ""


def _extract_content(data, extension, actual_type, findings):
    if actual_type == "ZIP archive":
        if extension in {".docx", ".docm", ".xlsx", ".xlsm"}:
            return _office_zip_text(data, extension, findings), []
        return _zip_members(data, findings)

    if extension in TEXT_EXTENSIONS or actual_type == "Text or HTML":
        decoded = data.decode("utf-8", errors="replace")[:MAX_EXTRACTED_TEXT_CHARACTERS]
        if extension in {".html", ".htm", ".xhtml"} or re.search(
            r"<\s*(?:html|form|a|body)\b", decoded, re.IGNORECASE
        ):
            soup = BeautifulSoup(decoded, "html.parser")
            urls = []
            for tag in soup.find_all(["a", "form", "iframe", "img", "script"]):
                for attr in ("href", "src", "action"):
                    target = tag.get(attr)
                    if isinstance(target, str):
                        urls.extend(_urls(target))
            if soup.find("form"):
                _finding(findings, "HTML form", "The attachment contains an HTML form that may collect submitted data.", "high")
            if soup.find(["iframe", "script"]):
                _finding(findings, "Active HTML content", "The attachment contains script or iframe elements; they were not executed.", "high")
            return soup.get_text(" ", strip=True), list(dict.fromkeys(urls))
        return decoded, _urls(decoded)

    if extension == ".pdf" and actual_type == "PDF document":
        try:
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                _finding(findings, "Encrypted PDF", "Text extraction is unavailable for this password-protected PDF.", "medium")
                return "", []
            if len(reader.pages) > MAX_PDF_PAGES:
                _finding(findings, "PDF page inspection limit reached", f"Only the first {MAX_PDF_PAGES} pages were inspected.", "medium")
            text = "\n".join(
                (page.extract_text() or "")
                for page in reader.pages[:MAX_PDF_PAGES]
            )[:MAX_EXTRACTED_TEXT_CHARACTERS]
            return text, _urls(text)
        except (PdfReadError, ValueError, KeyError, OSError):
            _finding(findings, "PDF could not be parsed", "The PDF structure is malformed or unsupported.", "medium")
            return "", []

    if extension in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".tif", ".tiff"}:
        try:
            with Image.open(io.BytesIO(data)) as image:
                metadata = {
                    "format": image.format,
                    "width": image.width,
                    "height": image.height,
                    "metadata_fields": sorted(str(key) for key in image.info),
                }
                return "", [], metadata
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
            _finding(findings, "Image metadata unavailable", "The image could not be safely decoded.", "medium")
            return "", [], {}

    if extension in {".docx", ".docm", ".xlsx", ".xlsm"} and actual_type != "ZIP archive":
        _finding(findings, "Office file signature mismatch", "The filename suggests an Office document, but the file is not a valid ZIP-based Office package.", "high")
    elif extension == ".pdf" and actual_type != "PDF document":
        _finding(findings, "PDF signature mismatch", "The filename ends in .pdf, but the file does not have a PDF signature.", "high")

    return "", []


def _scan_attachment(filename, data, external_consent):
    digest = hashlib.sha256(data).hexdigest()
    suffix = PurePosixPath(filename.replace("\\", "/")).suffix[:16]
    with tempfile.NamedTemporaryFile(
        prefix="phishguard-email-",
        suffix=suffix,
        delete=False,
    ) as sample:
        sample.write(data)
        sample_path = sample.name
    try:
        return analyze_file(
            sample_path,
            filename,
            len(data),
            digest,
            external_consent,
        )
    finally:
        Path(sample_path).unlink(missing_ok=True)


def analyze_attachment(filename, data, mime_type=None, external_consent=False):
    if not isinstance(data, bytes):
        raise TypeError("Attachment data must be bytes.")
    if len(data) > MAX_ATTACHMENT_BYTES:
        return {
            "filename": str(filename).replace("\\", "/").rsplit("/", 1)[-1],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": "skipped",
            "actual_type": "Not inspected",
            "claimed_mime": mime_type or "Not provided",
            "findings": [{
                "title": "Attachment exceeds size limit",
                "detail": f"Attachments over {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MiB are not inspected.",
                "severity": "medium",
            }],
            "extracted_urls": [],
            "scanners": {
                "file_type": "Not inspected",
                "engines": [{
                    "provider": "Local antivirus",
                    "status": "skipped",
                    "message": "Attachment exceeded the local inspection size limit.",
                }],
            },
        }

    safe_name = str(filename).replace("\\", "/").rsplit("/", 1)[-1][:180]
    extension = "." + safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    findings = []
    header = data[:16]
    if header.startswith(b"%PDF-"):
        actual_type = "PDF document"
    elif header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        actual_type = "ZIP archive"
    elif header.startswith(b"MZ"):
        actual_type = "Windows executable"
    elif header.startswith(b"\x7fELF"):
        actual_type = "ELF executable"
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        actual_type = "OLE compound document"
    elif header.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        actual_type = "Image"
    elif b"\x00" not in header and (
        extension in TEXT_EXTENSIONS | {".html", ".htm", ".xhtml"}
    ):
        actual_type = "Text or HTML"
    elif not data:
        actual_type = "Empty file"
    else:
        actual_type = "Unknown binary"

    if len(safe_name.rsplit(".", 2)) == 3 and extension in EXECUTABLE_EXTENSIONS:
        _finding(findings, "Double extension", "The filename uses an extra extension before an executable or script extension.", "high")
    if extension in EXECUTABLE_EXTENSIONS or actual_type in {
        "Windows executable", "ELF executable", "OLE compound document"
    }:
        _finding(findings, "Executable or active file", "This attachment is executable or may contain active content. Do not open it.", "high")

    expected_mime, _ = mimetypes.guess_type(safe_name)
    if mime_type and expected_mime and mime_type != expected_mime:
        _finding(findings, "Claimed MIME type differs from extension", f"The upload reports {mime_type}, while the filename normally maps to {expected_mime}.", "low")

    extracted_text = ""
    extracted_urls = []
    metadata = {}
    if actual_type == "Image":
        extracted_text, extracted_urls, metadata = _extract_content(
            data, extension, actual_type, findings
        )
    else:
        extracted = _extract_content(data, extension, actual_type, findings)
        if len(extracted) == 3:
            extracted_text, extracted_urls, metadata = extracted
        else:
            extracted_text, extracted_urls = extracted

    normalized_text = extracted_text.lower()
    if re.search(r"\b(?:verify (?:your )?password|enter (?:your )?(?:password|otp)|confirm (?:your )?account)\b", normalized_text):
        _finding(findings, "Credential collection language", "Extracted text asks for credentials or account verification.", "high")
    if re.search(r"\b(?:account suspended|urgent action required|payment overdue|gift card)\b", normalized_text):
        _finding(findings, "Social-engineering language", "Extracted text contains urgency, payment, or gift-card scam indicators.", "medium")

    return {
        "filename": safe_name,
        "extension": extension or "(none)",
        "claimed_mime": mime_type or "Not provided",
        "actual_type": actual_type,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "status": "analyzed",
        "extracted_urls": list(dict.fromkeys(extracted_urls)),
        "metadata": metadata,
        "findings": findings,
        "scanners": _scan_attachment(safe_name, data, external_consent),
    }
