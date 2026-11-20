document.addEventListener("DOMContentLoaded", () => {
    // A gated deployment answers 401 with the unlock URL; follow it once.
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
        const response = await nativeFetch(input, init);
        if (response.status === 401) {
            response
                .clone()
                .json()
                .then((body) => {
                    if (body && body.unlock_url) window.location.assign(body.unlock_url);
                })
                .catch(() => {});
        }
        return response;
    };

    document.querySelectorAll("[data-copy-target]").forEach((button) => {
        button.addEventListener("click", async () => {
            const source = document.getElementById(button.dataset.copyTarget);
            if (!source) return;
            const label = button.textContent;
            try {
                await navigator.clipboard.writeText(source.textContent.trim());
                button.textContent = "Copied";
                button.classList.add("is-copied");
            } catch {
                button.textContent = "Select and copy";
            }
            window.setTimeout(() => {
                button.textContent = label;
                button.classList.remove("is-copied");
            }, 2200);
        });
    });

    document.querySelectorAll("[data-sidebar-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
            const collapsed = document.body.classList.toggle("sidebar-collapsed");
            button.setAttribute("aria-expanded", String(!collapsed));
            button.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
        });
    });

    const urlInput = document.getElementById("url-input");
    const preview = document.querySelector("[data-url-preview]");
    const clearButton = document.querySelector("[data-clear-url]");
    const feedback = document.getElementById("url-feedback");
    const scanForm = document.querySelector("[data-scan-form]");

    if (urlInput && preview) {
        const previewHost = document.querySelector("[data-preview-host]");
        const previewPath = document.querySelector("[data-preview-path]");
        const previewLength = document.querySelector("[data-preview-length]");

        const updatePreview = () => {
            const value = urlInput.value.trim();
            clearButton.hidden = !value;

            if (!value) {
                preview.hidden = true;
                feedback.textContent = "No URL analyzed yet";
                return;
            }

            try {
                const parsed = new URL(value);
                preview.hidden = false;
                previewHost.textContent = parsed.hostname;
                previewPath.textContent = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;
                previewLength.textContent = `${value.length} chars`;
                feedback.textContent = parsed.protocol === "https:" ? "HTTPS link" : "HTTP link";
            } catch {
                preview.hidden = true;
                feedback.textContent = "Enter a complete URL";
            }
        };

        urlInput.addEventListener("input", updatePreview);
        urlInput.addEventListener("blur", () => {
            const value = urlInput.value.trim();
            if (!value || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return;
            if (!/^[\w.-]+\.[a-z]{2,}/i.test(value)) return;
            urlInput.value = `https://${value}`;
            updatePreview();
        });
        document.querySelectorAll("[data-example-url]").forEach((button) => {
            button.addEventListener("click", () => {
                urlInput.value = button.dataset.exampleUrl;
                updatePreview();
                urlInput.focus();
            });
        });

        clearButton.addEventListener("click", () => {
            urlInput.value = "";
            updatePreview();
            urlInput.focus();
        });
    }

    if (scanForm) {
        scanForm.addEventListener("submit", () => {
            const submitButton = scanForm.querySelector("[data-submit-button]");
            const submitLabel = scanForm.querySelector("[data-submit-label]");
            submitButton.disabled = true;
            submitLabel.textContent = "Analyzing…";
        });
    }

    const fileForm = document.querySelector("[data-file-form]");
    if (fileForm) {
        const fileInput = fileForm.querySelector("[data-file-input]");
        const dropzone = fileForm.querySelector("[data-file-dropzone]");
        const selectedFile = fileForm.querySelector("[data-selected-file]");
        const submitButton = fileForm.querySelector("[data-file-submit]");
        const submitLabel = fileForm.querySelector("[data-file-submit-label]");
        const errorMessage = fileForm.querySelector("[data-file-error]");
        const progress = fileForm.querySelector("[data-upload-progress]");
        const progressBar = fileForm.querySelector("[data-upload-bar]");
        const progressPercent = fileForm.querySelector("[data-upload-percent]");
        const progressLabel = fileForm.querySelector("[data-upload-label]");
        const maxUploadBytes = Number(fileForm.dataset.maxUploadBytes);

        const formatBytes = (bytes) => {
            if (bytes < 1024) return `${bytes} B`;
            const units = ["KB", "MB", "GB", "TB"];
            let size = bytes / 1024;
            let unit = 0;
            while (size >= 1024 && unit < units.length - 1) {
                size /= 1024;
                unit += 1;
            }
            return `${size.toFixed(1)} ${units[unit]}`;
        };

        const setSelectedFile = (file) => {
            errorMessage.hidden = true;
            if (!file) {
                selectedFile.hidden = true;
                dropzone.hidden = false;
                submitButton.disabled = true;
                submitLabel.textContent = "Choose a file to analyze";
                return;
            }
            dropzone.hidden = true;
            selectedFile.hidden = false;
            fileForm.querySelector("[data-selected-name]").textContent = file.name;
            fileForm.querySelector("[data-selected-size]").textContent = formatBytes(file.size);
            submitButton.disabled = file.size > maxUploadBytes;
            submitLabel.textContent = file.size > maxUploadBytes
                ? "File exceeds the upload limit"
                : "Analyze file";
            if (file.size > maxUploadBytes) {
                errorMessage.textContent = `This file exceeds the ${formatBytes(maxUploadBytes)} local upload limit.`;
                errorMessage.hidden = false;
            }
        };

        fileInput.addEventListener("change", () => setSelectedFile(fileInput.files[0]));
        fileForm.querySelector("[data-clear-file]").addEventListener("click", () => {
            fileInput.value = "";
            setSelectedFile(null);
        });

        ["dragenter", "dragover"].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.add("is-dragging");
            });
        });
        ["dragleave", "drop"].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.remove("is-dragging");
            });
        });
        dropzone.addEventListener("drop", (event) => {
            const [file] = event.dataTransfer.files;
            if (!file) return;
            const transfer = new DataTransfer();
            transfer.items.add(file);
            fileInput.files = transfer.files;
            setSelectedFile(file);
        });

        fileForm.addEventListener("submit", (event) => {
            event.preventDefault();
            const file = fileInput.files[0];
            if (!file || file.size > maxUploadBytes) return;

            errorMessage.hidden = true;
            submitButton.disabled = true;
            progress.hidden = false;
            progressLabel.textContent = "Uploading sample";
            const xhr = new XMLHttpRequest();
            xhr.open("POST", fileForm.action);
            xhr.setRequestHeader(
                "X-CSRF-Token",
                fileForm.querySelector('input[name="csrf_token"]').value
            );
            xhr.upload.addEventListener("progress", (uploadEvent) => {
                if (!uploadEvent.lengthComputable) return;
                const percent = Math.round((uploadEvent.loaded / uploadEvent.total) * 100);
                progressBar.style.width = `${percent}%`;
                progressPercent.textContent = `${percent}%`;
                if (percent === 100) progressLabel.textContent = "Preparing analysis";
            });
            xhr.addEventListener("load", () => {
                let response;
                try {
                    response = JSON.parse(xhr.responseText);
                } catch {
                    response = { error: "The server returned an unexpected response." };
                }
                if (xhr.status === 202 && response.url) {
                    window.location.assign(response.url);
                    return;
                }
                errorMessage.textContent = response.error || "The upload could not be completed.";
                errorMessage.hidden = false;
                progress.hidden = true;
                submitButton.disabled = false;
            });
            xhr.addEventListener("error", () => {
                errorMessage.textContent = "Network error during upload. Check your connection and try again.";
                errorMessage.hidden = false;
                progress.hidden = true;
                submitButton.disabled = false;
            });
            xhr.send(new FormData(fileForm));
        });
    }

    const fileResult = document.querySelector("[data-file-result]");
    if (fileResult && ["queued", "scanning"].includes(fileResult.dataset.status)) {
        const pollStatus = () => {
            fetch(fileResult.dataset.statusUrl, { headers: { Accept: "application/json" } })
                .then((response) => {
                    if (!response.ok) throw new Error("Status request failed.");
                    return response.json();
                })
                .then((result) => {
                    if (["complete", "failed"].includes(result.status)) {
                        window.location.reload();
                        return;
                    }
                    const message = fileResult.querySelector("[data-status-message]");
                    if (message) message.textContent = result.message;
                    window.setTimeout(pollStatus, 3000);
                })
                .catch(() => {
                    const message = fileResult.querySelector("[data-status-message]");
                    if (message) message.textContent = "Could not refresh status. Reload this page to try again.";
                });
        };
        window.setTimeout(pollStatus, 2500);
    }

    const emailForm = document.querySelector("[data-email-form]");
    const emailRiskMeter = document.querySelector("[data-risk-meter]");
    if (emailRiskMeter) {
        const riskBar = emailRiskMeter.querySelector("[data-risk-bar]");
        const score = Number(emailRiskMeter.getAttribute("aria-valuenow"));
        if (riskBar && Number.isFinite(score)) {
            riskBar.style.width = `${Math.max(0, Math.min(100, score))}%`;
        }
    }

    if (emailForm) {
        const emailInput = emailForm.querySelector("[data-email-input]");
        const emailCount = emailForm.querySelector("[data-email-count]");
        const emailSubmit = emailForm.querySelector("[data-email-submit]");
        const emailSubmitLabel = emailForm.querySelector("[data-email-submit-label]");
        const emailFile = emailForm.querySelector("[data-email-file]");
        const attachmentInput = emailForm.querySelector("[data-email-attachments]");
        const selectedFiles = emailForm.querySelector("[data-email-selected-files]");
        const maxCharacters = Number(emailForm.dataset.maxCharacters);
        const maxEmailUploadBytes = Number(emailForm.dataset.maxEmailUploadBytes);
        const maxAttachmentBytes = Number(emailForm.dataset.maxAttachmentBytes);
        const updateEmailLength = () => {
            const length = emailInput.value.length;
            const hasFile = emailFile.files.length > 0;
            emailCount.textContent = `${length.toLocaleString()} / ${maxCharacters.toLocaleString()}`;
            emailSubmit.disabled = (!length && !hasFile) || length > maxCharacters;
            emailSubmitLabel.textContent = length
                ? "Analyze email"
                : hasFile
                    ? "Analyze uploaded email"
                    : "Paste or upload an email to analyze";
        };
        emailInput.addEventListener("input", updateEmailLength);
        emailFile.addEventListener("change", updateEmailLength);
        attachmentInput.addEventListener("change", () => {
            const files = Array.from(attachmentInput.files);
            selectedFiles.textContent = files.length
                ? files.map((file) => file.name).join(", ")
                : "";
        });
        emailForm.addEventListener("submit", (event) => {
            const emailFileTooLarge = emailFile.files.length > 0
                && emailFile.files[0].size > maxEmailUploadBytes;
            const attachmentsTooLarge = attachmentInput.files.length > 10
                || Array.from(attachmentInput.files).some((file) => file.size > maxAttachmentBytes);
            if (emailFileTooLarge) {
                event.preventDefault();
                emailSubmit.disabled = false;
                emailSubmitLabel.textContent = "Email file exceeds the upload limit";
            } else if (attachmentsTooLarge) {
                event.preventDefault();
                emailSubmit.disabled = false;
                emailSubmitLabel.textContent = "Check attachment count and size";
            } else {
                emailSubmit.disabled = true;
                emailSubmitLabel.textContent = "Analyzing message…";
            }
        });
        updateEmailLength();
    }

});
