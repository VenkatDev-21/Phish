/**
 * Demo status for the landing page. Always answers 200 so the page can still
 * render the console links even when the Render API is asleep or missing.
 */
export default async function handler(request, response) {
  response.setHeader("Cache-Control", "no-store");

  const appUrl = (process.env.PHISHGUARD_APP_URL || "").replace(/\/+$/, "");
  if (!appUrl) {
    return response.status(200).json({
      online: false,
      appUrl: "",
      error:
        "PHISHGUARD_APP_URL is not set on this Vercel project, so the live demo has nowhere to send requests.",
    });
  }

  try {
    const upstream = await fetch(`${appUrl}/api/v1/health`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(6000),
    });
    const body = await upstream.json().catch(() => ({}));
    return response.status(200).json({
      online: upstream.ok,
      appUrl,
      environment: body.environment || "hosted",
      historyGate: Boolean(body.history_gate),
    });
  } catch {
    return response.status(200).json({
      online: false,
      appUrl,
      error: "The PhishGuard API did not respond. Render may be cold-starting.",
    });
  }
}
