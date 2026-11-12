/**
 * Detect whether the frontend is currently running inside the standalone desktop client
 * (e.g. pywebview wrapper) rather than a normal web browser.
 */
export function isDesktopClient(): boolean {
  if (typeof window === 'undefined') return false
  if (Boolean((window as unknown as { pywebview?: unknown }).pywebview)) return true
  try {
    if (window.sessionStorage.getItem('cpm_is_desktop') === '1') return true
    if (new URLSearchParams(window.location.search).get('desktop') === '1') {
      window.sessionStorage.setItem('cpm_is_desktop', '1')
      return true
    }
  } catch {}
  if (typeof navigator !== 'undefined') {
    const ua = navigator.userAgent
    // macOS WKWebView does not contain "Safari/" or "Chrome/" or "Firefox/"
    if (
      ua.includes('Macintosh') &&
      ua.includes('AppleWebKit') &&
      !ua.includes('Safari/') &&
      !ua.includes('Chrome/') &&
      !ua.includes('Firefox/')
    ) {
      return true
    }
  }
  return false
}
