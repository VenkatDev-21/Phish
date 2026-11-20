/**
 * Same-origin proxy for the hosted PhishGuard API.
 *
 * The browser only ever talks to this Vercel function, so the Render host name
 * stays in a server-side environment variable and CORS never enters the picture.
 */
const TIMEOUT_MS = 8000;

export default async function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");

  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ error: "Use POST with a JSON body." });
  }

  const appUrl = (process.env.PHISHGUARD_APP_URL || "").replace(/\/+$/, "");
  if (!appUrl) {
    return response.status(503).json({
      error:
        "PHISHGUARD_APP_URL is not set on this Vercel project. Add it in Project Settings → Environment Variables and redeploy.",
    });
  }

  const url =
    request.body && typeof request.body.url === "string" ? request.body.url : "";
  if (!url.trim()) {
    return response.status(400).json({ error: "Send a JSON body with a url field." });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const upstream = await fetch(`${appUrl}/api/v1/scan/url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    const payload = await upstream.text();
    response.status(upstream.status);
    response.setHeader("Content-Type", "application/json; charset=utf-8");
    return response.send(payload);
  } catch (error) {
    const timedOut = error && error.name === "AbortError";
    return response.status(timedOut ? 504 : 502).json({
      error: timedOut
        ? "The PhishGuard API did not answer in time. Render may still be waking up."
        : "The PhishGuard API could not be reached.",
    });
  } finally {
    clearTimeout(timer);
  }
}
