//! The wearer's web app, compiled into the binary so there is nothing to deploy
//! next to it. Served with a strict Content-Security-Policy: the app has no
//! inline scripts or styles, and may only talk to this server.

use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

struct Asset {
    path: &'static str,
    mime: &'static str,
    bytes: &'static [u8],
    /// Pages and code revalidate every time so an updated server is picked up at once.
    cache: &'static str,
}

const REVALIDATE: &str = "no-cache";
const ICON_CACHE: &str = "public, max-age=86400";

const ASSETS: &[Asset] = &[
    Asset { path: "/", mime: "text/html; charset=utf-8", bytes: include_bytes!("../web/index.html"), cache: REVALIDATE },
    Asset { path: "/app.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../web/app.js"), cache: REVALIDATE },
    Asset { path: "/core.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../web/core.js"), cache: REVALIDATE },
    Asset { path: "/relay.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../web/relay.js"), cache: REVALIDATE },
    Asset { path: "/sw.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../web/sw.js"), cache: REVALIDATE },
    Asset { path: "/app.css", mime: "text/css; charset=utf-8", bytes: include_bytes!("../web/app.css"), cache: REVALIDATE },
    Asset { path: "/manifest.webmanifest", mime: "application/manifest+json", bytes: include_bytes!("../web/manifest.webmanifest"), cache: REVALIDATE },
    Asset { path: "/icons/icon.svg", mime: "image/svg+xml", bytes: include_bytes!("../web/icons/icon.svg"), cache: ICON_CACHE },
    Asset { path: "/icons/icon-180.png", mime: "image/png", bytes: include_bytes!("../web/icons/icon-180.png"), cache: ICON_CACHE },
    Asset { path: "/icons/icon-192.png", mime: "image/png", bytes: include_bytes!("../web/icons/icon-192.png"), cache: ICON_CACHE },
    Asset { path: "/icons/icon-512.png", mime: "image/png", bytes: include_bytes!("../web/icons/icon-512.png"), cache: ICON_CACHE },
    Asset { path: "/icons/icon-maskable-512.png", mime: "image/png", bytes: include_bytes!("../web/icons/icon-maskable-512.png"), cache: ICON_CACHE },
];

pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Anything that is not an API route: the app, or a 404.
pub async fn serve(uri: Uri) -> Response {
    let path = match uri.path() {
        "/index.html" => "/",
        p => p,
    };
    match ASSETS.iter().find(|a| a.path == path) {
        Some(a) => (
            [(header::CONTENT_TYPE, HeaderValue::from_static(a.mime)), (header::CACHE_CONTROL, HeaderValue::from_static(a.cache))],
            a.bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

#[cfg(test)]
pub fn asset(path: &str) -> Option<&'static [u8]> {
    ASSETS.iter().find(|a| a.path == path).map(|a| a.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(path: &str) -> String {
        String::from_utf8(asset(path).unwrap_or_else(|| panic!("{path} is not embedded")).to_vec()).unwrap()
    }

    #[test]
    fn everything_the_page_and_service_worker_load_is_embedded() {
        let html = text("/");
        let mut wanted: Vec<String> = Vec::new();
        for attr in ["href=\"", "src=\""] {
            for part in html.split(attr).skip(1) {
                wanted.push(part.split('"').next().unwrap().to_string());
            }
        }
        // The offline shell the service worker precaches must exist too.
        let sw = text("/sw.js");
        let shell = sw.split("const SHELL = [").nth(1).unwrap().split(']').next().unwrap();
        for item in shell.split(',') {
            wanted.push(item.trim().trim_matches('\'').to_string());
        }
        for p in wanted.iter().filter(|p| p.starts_with('/')) {
            assert!(asset(p).is_some(), "{p} is referenced but not served");
        }
        assert!(wanted.len() >= 8);
    }

    #[test]
    fn the_app_uses_no_inline_script_or_style_because_the_policy_forbids_them() {
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe-inline"));
        let html = text("/");
        assert!(!html.contains("style="), "inline style attribute in index.html");
        assert!(!html.contains("onclick") && !html.contains("<script>"), "inline script in index.html");
        // app.js builds markup from strings: a style attribute or inline handler there would be blocked too.
        let app = text("/app.js");
        assert!(!app.contains("style=\""), "inline style attribute in app.js templates");
        assert!(!app.contains(" onclick=") && !app.contains(" onsubmit="), "inline handler in app.js templates");
    }

    #[test]
    fn the_manifest_is_valid_and_points_at_real_icons() {
        let m: serde_json::Value = serde_json::from_str(&text("/manifest.webmanifest")).unwrap();
        assert_eq!(m["display"], "standalone");
        assert_eq!(m["start_url"], "/");
        for icon in m["icons"].as_array().unwrap() {
            let src = icon["src"].as_str().unwrap();
            assert!(asset(src).is_some(), "{src}");
        }
    }
}
