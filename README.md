# Hacktor

### A ZAP 2.17.0 add-on for HTTP access-control bypass and OAuth tampering — 7800+ techniques across 40+ families for 401/403 bypass, auth/authz probing, HTTP smuggling, cache poisoning, injection probing and OAuth 1.0a/2.0/OIDC tampering.

[![license](https://img.shields.io/badge/license-MIT-3DA639)](/ArkhaMahn/Hacktor/blob/main/LICENSE) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-B5BAB6)](https://github.com/ArkhaMahn/Hacktor/issues)

---

# Hacktor — ZAP add-on

A [ZAP](https://www.zaproxy.org/) add-on that probes authorization- and authentication-boundaries from a single base request: it rebuilds the request hundreds to thousands of ways — HTTP verbs, request-line and path mutations, header confusion and duplication, host/authorization tampering, encoding tricks, TE/CL and request-smuggling framing, scheme tampering, cache poisoning, raw-wire aberrations — plus a dedicated **TamperOauth** tab that auto-detects OAuth 1.0a / 2.0 / OpenID Connect requests and runs its own Classic/Rare/Novel tamper catalogue against them. Every probe is sent against the live target, its response compared byte-for-byte with a baseline, and each mutation is classified as a **candidate bypass**, **suppressed false positive** (error page / rate-limit / WAF block), or **no change**.

> **Status: alpha.** Built and verified for ZAP 2.17.0. The extension loads cleanly with no errors. Please report any issues.

---

## Table of Contents

- [Overview](#overview)
- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [The bypass engine](#the-bypass-engine)
    - [Techniques, families and tiers](#techniques-families-and-tiers)
    - [Verdicts and false-positive suppression](#verdicts-and-false-positive-suppression)
    - [The raw-wire sender](#the-raw-wire-sender)
    - [The WAF-encoding ladder](#the-waf-encoding-ladder)
    - [Body-parameter fuzzing](#body-parameter-fuzzing)
    - [Out-of-band callback probes](#out-of-band-callback-probes)
    - [The injection catalogue](#the-injection-catalogue)
- [The OAuth tamper lab](#the-oauth-tamper-lab)
    - [Endpoint detection](#endpoint-detection)
    - [Flow identification](#flow-identification)
    - [The technique catalogue](#the-technique-catalogue)
    - [Per-parameter encoding and canonicalization](#per-parameter-encoding-and-canonicalization)
- [The UI](#the-ui)
    - [The Target tab](#the-target-tab)
    - [The TamperOauth tab](#the-tamperoauth-tab)
    - [The Techniques tab](#the-techniques-tab)
    - [The Results tab](#the-results-tab)
    - [The Log tab](#the-log-tab)
    - [The Advanced tab](#the-advanced-tab)
    - [Dialogs and context menu](#dialogs-and-context-menu)
- [Run controls and shared knobs](#run-controls-and-shared-knobs)
- [ZAP integration](#zap-integration)
- [Requirements](#requirements)
- [Build](#build)
- [Install in ZAP](#install-in-zap)
- [Usage](#usage)
- [Behaviour notes](#behaviour-notes)
- [Security notes](#security-notes)
- [Development](#development)
- [Credits](#credits)
- [License](#license)

---

## Overview

Authorization boundaries are rarely enforced on the request as the browser sent it — proxies, WAFs, framework routers and application logic each parse a slightly different request, and that parser differential is the bypass. Hacktor automates exploring that differential on one message at a time.

Point it at any HTTP request from the Sites tree, History or Search (right-click → **Send to Hacktor**), fetch a baseline, and let it decide what to do next:

```
PHASE 1 — baseline
   GET /admin/panel HTTP/1.1  ->  401 (1234 bytes)

PHASE 2 — 7800+ mutations, each compared to the baseline
   "Path Normalization | Trailing '.', double slash"   -> 200  (8124 bytes)  CANDIDATE BYPASS
   "X-Original URL    | /admin/panel via header"       -> 200  (8122 bytes)  CANDIDATE BYPASS
   "Host Header       | localhost"                     -> 403  (1160 bytes)  Suppressed (error page)
   "Raw Aberrations   | obs-fold in Host"              -> 401  (1234 bytes)  No change
```

Hacktor is **active by design** — it is a live probing/verification tool, so use it only against systems you are authorized to test. Out-of-band callback probes (Burp Collaborator / Interactsh / Canarytokens) are opt-in, and everything is throttled, pausable and bounded.

Feature | Description
--- | ---
7800+ techniques | catalog × placements × tiers × WAF encodings × body params × OOB templates, generated per-target
40+ families | 23 injection/proxy-trust catalog classes + 40+ request-mutation technique families
Classic/Rare/Novel tiers | gate by technique obscurity; Novel adds segment-prepend, query-append and body-param injection
Granular control | per-row and per-family enable/disable, custom techniques, duplicate/edit/remove
False-positive suppression | error-page and length-ratio heuristics classify 200/302/404 "bypasses" that are really branded blocks
Raw-wire sender | literal `#` fragments, malformed request lines, HTTP/2 pseudo-headers and TE/CL framing survive to the socket
OOB callbacks | `{{OOB}}` templates replaced with your callback URL at rebuild time, on 4 placements per template
TamperOauth tab | auto-detect OAuth 1.0a/2.0/OIDC, full URL/param/value control with per-value encoding, 122 tamper techniques
Rich results | sortable/filterable table, full request/response viewers, CSV export, copy as cURL, resend
Shared knobs | threads, rate limit, timeout, max probes, exponential backoff on 403/429, follow redirects, stop on first candidate

## What it does

- **Access-control (401/403) bypass probing** — for a base request it generates and sends thousands of one-variable mutations targeting the ways frameworks and proxies decide "this request is allowed": HTTP methods and malformed verbs, path normalization and segment mutations, header case/confusion/duplication, IPv4/IPv6/host/authorization tampering, encoding chains, fragments, homoglyphs, padding, matrix parameters, backslash/UNC paths, X-Original-URL / X-Forwarded-* prefix tricks, HTTP/2 pseudo-headers, TE/CL and request-smuggling framing, hop-by-hop header suppression, referer-trust games, scheme tampering and raw-wire aberrations.
- **Injection probing** — 23 vulnerability classes (SQLi, XSS, command injection, Shellshock, path traversal, SSRF, SSTI, NoSQLi, open redirect, XXE, LDAPi, Log4Shell, prototype pollution, insecure deserialization, CRLF, SSI, RFI/LFI, CSV injection, and the proxy/IP-trust header families) are fired across 8 request placements — headers, User-Agent, each path segment (pre/post), root path, root query, existing query value/append, and real body parameters parsed out of form, multipart, JSON and XML bodies.
- **WAF-beating encoding ladders** — every catalogue payload is re-emitted through URL×1/×2/×3, Base64, URL-safe Base64, ASCII hex, HTML entities and overlong UTF-8, so a WAF that decodes once and an application that decodes twice diverge.
- **Out-of-band proof** — command-execution, XXE, SSRF and Log4Shell templates that point `{{OOB}}` back at your callback server; a hit proves server-side interpretation of the payload.
- **OAuth tampering** — a complete second lab (TamperOauth) that parses an OAuth request, identifies the endpoint and flow, exposes every query/body parameter and value (with per-value encoding and canonicalization), and runs 122 Classic/Rare/Novel OAuth techniques: redirect_uri confusion, PKCE downgrades, grant/response-type switches, state & nonce replay, consent and session forcing, client-identity attacks and OAuth 1.0a signature games.
- **Granular, persistent control** — techniques can be toggled per-row or per-family, filtered, re-tiered live, or replaced with your own custom techniques (path replacement, header override, placement probe). Custom header rules, fixed headers, tier gates, results retention and OOB URL all persist in ZAP's config.
- **Research-friendly results** — every candidate row keeps its full request/response message for immediate inspection or replay, exports to CSV, and copies as a `curl` command.

## How it works

Everything funnels through one entry point: `HacktorEngine.buildTechniques(HttpMessage)` reconstructs the target into a `PathContext` (original path, clean base path, query, segments, last segment, parent), then every mutation is a small compiled mutation that is cloned, applied to the base message, sent and compared against the single baseline captured at the start of the run.

```
              base request (Request | History | custom)
                          │
                          ▼
            HacktorEngine.buildTechniques(msg)
        ┌──────────────┬───────────┬──────────────┐
        ▼              ▼           ▼              ▼
  16 inline       44 technique    VulnCatalog     WAF encoders
  families        builders        23 classes      URL×1/2/3, B64,
  (Methods,       (Fragment,      × tiers ×       B64U, Hex, HTML,
   Case, Path,     Smuggling,     8 placements    Overlong UTF-8
   Headers, …)     Raw Aberr., …)                 + OOB templates
        └──────────────┬───────────┬──────────────┘
                       ▼
             List<Technique>  (7800+ on a typical
               each: family, label, tier, needsRawWire,
               enabled, compiled apply(HttpMessage))
                       │  tier gate (Classic/Rare/Novel)
                       ▼
               runOne(technique, sender)
        ┌───────────┴───────────┐
        ▼                       ▼
   needsRawWire?            HttpSender
   → RawHttpSender          (ZAP standard)
   (literal #, malformed    │
   request line, h2 pseudo, │
   TE/CL framing, WAF ladders)
        └───────────┬───────────┘
                    ▼
          baseline comparison
   classifyVerdict(status, isErr, realChange)
        ┌──────────┬───────────┬──────────────┐
        ▼          ▼           ▼              ▼
    CANDIDATE   SUPPRESSED   NO_CHANGE     dropped
    (real       (looks like  (status &      (byte-identical
     bypass)     error page / body same as  to baseline —
                  length near  baseline)     not even shown)
                  baseline)
                    │
                    ▼
        Results table + Log + Request/Response viewers
        CSV export · resend · copy as cURL
```

The OAuth lab mirrors this architecture with its own prebuilt catalogue: `OauthEngine.parse()` turns a URL (or the form-body of a message) into a `Context` of ordered `Param`s with raw wire bytes preserved; each of the 122 `OauthTech` generators copies that context, applies a mutation (`set`/`add`/`remove`/`duplicate`), re-encodes it, rebuilds the exact wire target with `HacktorEngine.setLiteralPath` (via the `X-Hacktor-WirePath` side channel) and sends it through the same verdict pipeline. The whole run is a flat sequence of independent probes, so it parallelizes freely and stops cleanly at any point.

## The bypass engine

### Techniques, families and tiers

A *technique* is one atomic, compilable mutation of the base request. Techniques are grouped by *family* (a named category in the Techniques tab) and graded into three *tiers*:

| Tier | Meaning |
| --- | --- |
| **Classic** | documented in textbooks and OWASP references — standard methods, dot-segments, common headers |
| **Rare** | unusual encodings and less common sinks — inline-obfuscated encodings, sibling-subdomain referers, alternate ports |
| **Novel** | unexpected-by-server forms — double/triple-encoded layers, overlong UTF-8, Tomcat `;jsessionid`, fullwidth/division slashes, cloud-metadata SSRF, CRLF-folding |

The catalogue multiplies: 308 tiered injection payloads across 23 classes × 8 placements (6 for Classic, 8 once Novel is enabled) × every detected path segment × WAF encodings × real body parameters × 31 OOB templates — so the exact count is per-target and typically lands in the thousands (hence "7800+ techniques across 40+ families"). A handful of emblematic families:

- **Path & request-line**: Path Normalization (dot/encoded/overlong/mid-dot/trailing-dot, `;jsessionid`), Path Append/Format Suffix/Version Path/Segment Dup/Wildcard/Matrix Params, Absolute URI, Null Byte, Backslash (UNC) paths, Padding (`%20`), Unicode Zero-Width, Homoglyphs, HTTP Version, Request Line (asterisk/authority/path-only/no-version/double-space), Lowercase Method.
- **Headers**: Header Case, Header Confusion (duplicate CL, CL+TE stacking), Header Normalization, API Headers, Connection/Hop-by-Hop suppression, Host Header, X-Original URL, X-Forwarded Prefix, Referer Trust, Authorization / Auth Forwarding, Cookies, Content-Type, obs-fold aberrations.
- **Framing & wire**: HTTP/2 pseudo-headers (`:method`/`:path`/`:authority`/`:scheme`/`:protocol`, case and duplicate tricks), TE/CL and Transfer-Encoding framing, Request Smuggling (`SMT_TE`, `SMT_CL`, `SMT_TE_CL`, CL:0 bodies), Scheme Tampering (h2c/websocket/SPDY upgrade), Raw Aberrations (PRI preface, NUL header names, whitespace methods).
- **Semantics**: Prototype Pollution, JSON Body, Method Override, IP Combo, Fragment, Segment Dot/Case/Mix/Letter variants, encoding chains, WAF encoding, Body Params, Inference (problematic-character probes across every placement).

### Verdicts and false-positive suppression

Each probe response is compared against the baseline captured at run start, and classified by `classifyVerdict(status, isErr, realChange)`:

| Verdict | Rule |
| --- | --- |
| `CANDIDATE` | response status is 200/201/202/204, **or** status differs from baseline and is not 401/403/400 |
| `SUPPRESSED` | status changed but the body looks like an error page |
| `NO_CHANGE` | no real change; byte-identical repetitions are dropped entirely from the results |

The `SUPPRESSED` class is the anti-noise design. `looksLikeErrorPage()` fires for `200/404/302/301` responses when the body matches a broad error-page marker regex (`access.denied`, `forbidden`, `unauthorized`, `error`, `exception`, `invalid.token`, `permission.denied`, `login.required`, `blocked`, `captcha` — 40+ markers, case-insensitive) **or** when the body length lands within ±12% of the baseline length (the "same branded page, different status" tell). A "200 bypass" that is really a branded "access denied" page therefore shows up as `SUPPRESSED`, not as a candidate. This also powers the **suppress custom error pages** option and the optional **exponential backoff** pacer, which recognizes 429 and 403 WAF/rate-limit blocks and spaces requests out from 1s to 30s.

### The raw-wire sender

ZAP's normal `HttpSender` (commons-httpclient) rebuilds the request line from parsed URI parts — so a literal `#` fragment is silently dropped, a crafted request line is re-normalized, and hand-built TE/CL vectors can be lost. `RawHttpSender` is a deliberately small, best-effort raw-socket sender that writes the exact bytes:

- **Exact request head** — the header block is serialized verbatim (ISO-8859-1) preserving casing, duplicates, obs-fold continuations, whitespace and any abberation; arbitrary method and version strings (`HTTP/0.9`, no-version, CRLF-injected versions) survive.
- **Exact request target** — literal `#` fragments, absolute-form targets, asterisk/authority forms, overlong `%20` padding and backslash/UNC paths are written byte-for-byte via the `X-Hacktor-WirePath` side channel (a display-only header that both senders strip before the bytes hit the wire).
- **TLS + proxy aware** — plaintext sockets, `SSLConnector` for TLS, and make-or-break parity with ZAP's proxy-chain decisions (absolute-form when a proxy is in play).
- **Robust response parsing** — 64 KiB response-header cap, 8 MiB body cap, Content-Length / chunked (with trailers) / read-until-EOF framing, plus a `X-Hacktor-Timing` side channel that surfaces precise `req`/`res` timings for the results table.
- **Always reversible** — on any failure it returns `false` and the engine falls back to the normal `HttpSender`, so a raw-only technique never dies just because the raw path hiccuped.

Techniques that *require* raw-wire sending (fragments, malformed request lines/verbs, HTTP/2 pseudo-headers, TE/CL smuggling, obs-fold, hop-by-hop suppression, lowercase/whitespace methods, and every WAF-encoding placement) are flagged `needsRawWire` at build time; the UI also exposes a master **"Raw wire for ambiguous requests"** toggle.

### The WAF-encoding ladder

The `PayloadEncoder` engine mirrors the transforms of the **Recode** ZAP add-on: URL×1/×2/×3, Base64, URL-safe Base64, ASCII hex, HTML entities (decimal), and overlong UTF-8 (only `/ . < > ' " = ; #` recast as two-byte `%c0%80`-style sequences). Each catalogue payload is re-emitted through these encoders at header/query/UA placements, and because `URI.setPath()` would re-escape the `%` and "shift the ladder by one", every encoded placement is routed through the raw-wire sender so the layered `%253C…` bytes reach the server intact — preserving the *WAF-decodes-once, app-decodes-twice* differential these families exploit.

### Body-parameter fuzzing

`BodyParams` parses request bodies regardless of content type — `application/x-www-form-urlencoded`, `multipart/form-data`, JSON (a minimal recursive-descent parser, no external JSON library) and XML (DOM-based, XXE-hardened: DOCTYPE/external entities disabled, secure processing on) — and produces tracked `Param`s with exact value spans. Unknown content types fall back to an opaque whole-body parameter. Catalogue payloads are applied to every detected parameter with `REPLACE`/`APPEND`/`PREPEND` (and **`INJECT`** of a brand-new `hacktor` parameter for Novel-tier payloads when the format allows), keeping `Content-Length` consistent on every rewrite.

### Out-of-band callback probes

When an OOB URL is configured (Tools → … → Target tab → **Out-of-Band Callbacks**, persisted as `hacktor.oobUrl`), every template containing `{{OOB}}` is replicated with the URL substituted at rebuild time, across four placements: the class's default header, `User-Agent`, an existing query parameter value, and the root query. A callback hit on Burp Collaborator / Interactsh / Canarytokens proves server-side interpretation of the payload — command execution, SSRF, XXE (external DTD) or Log4Shell JNDI lookup — while Hacktor itself never needs to probe the target to confirm.

### The injection catalogue

`VulnCatalog` is the shared payload store (23 classes, 308 tiered payloads + 31 OOB templates), drawn from common bypass sets and the ProjectDiscovery nuclei-templates repository:

| Class | Default header | Sample payloads |
| --- | --- | --- |
| SQL Injection | `X-Forwarded-For` | `1'/*!50000OR*/1=1--`, `1' OR SLEEP(0)--`, `' UNION SELECT NULL--` |
| XSS | `User-Agent` | `<svg/onload=alert(1)>`, `<details open ontoggle=alert(1)>`, `%3Cscript%3E…` |
| Command Injection | `X-Forwarded-For` | `;id`, `` `id` ``, `$(id)`, `%0Aid%0A` |
| Shellshock | `Referer` | `() { :; }; /usr/bin/id`, `%0d%0a() { :; }; …` |
| Path Traversal | `Referer` | `../../../etc/passwd`, `..%252f..%252f…`, `%c0%ae%c0%ae/…`, `php://filter/…` |
| SSRF | `X-Forwarded-For` | `http://2130706433/`, `http://169.254.169.254/latest/meta-data/`, `gopher://127.0.0.1:6379/_` |
| SSTI | `User-Agent` | `{{7*7}}`, `${7*7}`, `#{7*7}`, Jinja/Python RCE gadget |
| NoSQL Injection | `X-Forwarded-For` | `{$ne:null}`, `$regex=.*`, `"$where":"sleep(0)"` |
| Open Redirect | `Referer` | `//evil.com`, `///evil.com`, `\evil.com`, `%00//evil.com` |
| XXE | `Referer` | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`, `expect://id`, `jar:file://…` |
| LDAP Injection | `X-Forwarded-For` | `*`, `*)(uid=*`, `*)(|(objectClass=*`, `%2a)(uid=*` |
| Log4Shell | `X-Forwarded-For` | `${jndi:ldap://127.0.0.1/a}`, `${${lower:j}ndi:…}`, `${jndi:ldap%3a//…}` |
| Prototype Pollution | `X-Forwarded-For` | `__proto__[pe]=1`, `constructor[prototype][pe]=1`, `["__proto__","pe","1"]` |
| Insecure Deserialization | `Cookie` | `rO0ABXQABHRlc3Q=`, `O:8:"stdClass":0:{}`, `KGRwMApT…`, `{"$type":"System.Windows.Data.ObjectDataProvider,…}` |
| CRLF Injection | `Referer` | `%0d%0aX-Hacktor: 1`, `%250d%250a…`, `\u000d%\u000a…` |
| SSI Injection | `Referer` | `<!--#exec cmd="/usr/bin/id"-->`, `<!--#include virtual="/proc/self/environ"-->` |
| File Inclusion | `Referer` | `php://input`, `data://text/plain;base64,…`, `zip://archive.zip#shell.php`, `jar:http://…` |
| CSV Injection | `Referer` | `=HYPERLINK("http://…","pwn")`, `+cmd|'/c calc'!A0`, BOM+formula |
| Proxy Header Trust | `X-Forwarded-For` | `127.0.0.1`, `169.254.169.254`, `999.999.999.999`, `127.0.0.1, 8.8.8.8`, `0x7f000001`, `2130706433`, `127.1` |
| Cloudflare Headers | `CF-Connecting-IP` | same IP-spoof ladder |
| Akamai Headers | `Akamai-X-Forwarded-For` | same IP-spoof ladder |
| Real-IP Headers | `X-Real-IP` | same IP-spoof ladder |
| Forwarded Header Trust | `Forwarded` | `for=127.0.0.1`, `for="[::1]"`, `proto=https;for=…`, `host=admin.internal;…` |

The four IP-trust families exist for a reason: origins that trust a client IP only when it arrives through a trusted edge (XFF/CF/Akamai/Real-IP set) can be made to accept attacker-supplied IPs, defeating allow-lists, geo/anti-DDoS and rate-limit buckets, and exposing origin-only routes. Placement is handled by a shared engine with 8 placement kinds (`HDR`, `UA`, `SEG+`, `SEG-`, `ROOT-P`, `ROOT-Q`, `QREP`, `QAPP`), each with a short tag shown in the techniques table.

## The OAuth tamper lab

`OauthEngine` is a second, self-contained lab — reachable via the **TamperOauth** tab and fired automatically whenever an OAuth-shaped URL is sent to Hacktor.

### Endpoint detection

`parse()` accepts a raw URL or an `HttpMessage` (merging form-body params when the body is `application/x-www-form-urlencoded`, then re-running detection — a body `grant_type`/`scope` can change the endpoint verdict). Detection is case-insensitive substring matching on the path, in strict priority order:

| Endpoint | Detected by |
| --- | --- |
| `AUTHORIZE` | path contains `authorize` |
| `INTROSPECT` | path contains `introspect` |
| `REVOKE` | path contains `revoke` / `endsession` |
| `USERINFO` | path contains `userinfo` / `user_info` |
| `LOGOUT` | path contains `logout` / `idp_exit` |
| `WELL_KNOWN` | path contains `well-known` / `jwks` |
| `TOKEN` | path contains `token` |
| `OTHER` | OAuth-shaped request (parameter-detected) |

A request counts as OAuth when any of 33 standard OAuth 2.0/OIDC parameter names appear (`response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `grant_type`, `id_token`, …), or any of 10 OAuth 1.0a signatures (`oauth_consumer_key`, `oauth_signature`, `oauth_timestamp`, `oauth_nonce`, `oauth_version`, …).

### Flow identification

The detected context is labelled with a human flow description — **OAuth 1.0a request**, **OAuth 2.0 Implicit flow**, **OIDC Implicit**, **OIDC Hybrid**, **OAuth 2.0 Authorization Code flow** (annotated `(PKCE downgrade-ready)` when `code_challenge_method=plain`, else `(PKCE: <method>)`), **token exchange**, **token introspection**, **revocation/end-session**, **userinfo**, **discovery**, **logout** or **OAuth-shaped request**.

### The technique catalogue

122 built-in tamper techniques in 12 categories (71 Classic / 20 Rare / 31 Novel), each an immutable generator over a per-run copy of the context — so base state is never mutated:

| Category | Total | C | R | N | Highlights |
| --- | --- | --- | --- | --- | --- |
| Redirect URI | 22 | 10 | 6 | 6 | external host takeover, sibling-subdomain loosening, prefix-match, at-sign/backslash userinfo, fragment host-injection, scheme-relative, loopback, trailing-dot FQDN, cloud-metadata SSRF, gopher, homoglyphs, overlong-UTF-8 slash, CRLF-folding |
| Response Type | 7 | 4 | 2 | 1 | downgrade to implicit token, force `id_token`, hybrid, non-standard `password`, polluted duplicate |
| Scope | 9 | 5 | 2 | 2 | remove/empty/wildcard/privileged-literal scope, all_claims, newline-delimited |
| State/CSRF | 7 | 4 | 1 | 2 | remove/empty/fixed-attacker state, duplicate reuse, multi-line, RTL |
| PKCE | 7 | 4 | 1 | 2 | remove challenge, downgrade to `plain`, truncated, challenge/method mismatch |
| Grant Type | 11 | 6 | 2 | 3 | switch to client_credentials/password/refresh, JWT-bearer, device-code, token-exchange, pollution |
| Consent Objects | 9 | 4 | 3 | 2 | code replace/remove/duplicate, refresh remove/empty/replay, MAC/JWT token_type |
| Client Identity | 9 | 6 | 1 | 2 | remove/empty client_id, attacker literal, secret removal/empty/literal |
| OIDC Session | 20 | 15 | 0 | 5 | force consent/login, prompt games, `max_age` bounds, login_hint/acr_values injection, nonce remove/empty/fixed |
| Transport | 8 | 7 | 0 | 1 | `response_mode` fragment/query/form_post, fragment-on-code-flow, display=popup/touch/wap |
| OIDC Artifacts | 5 | 1 | 1 | 3 | id_token duplicate, `request_uri` injection, request-object games |
| OAuth 1.0a | 8 | 5 | 1 | 2 | version bump/downgrade, PLAINTEXT/weak-MAC signatures, consumer-key empty, timestamp/nonce replay |
| **Total** | **122** | **71** | **20** | **31** | |

Each technique records a `require` gate (generates only when the base request has the needed parameters — e.g. `code_challenge` for PKCE attacks) and an `addIfAbsent` list (parameters it will inject when absent, such as `max_age`, `claims`, `resource`, `audience`, `nonce`, `request_uri`). Notable attack classes built in: **authorization-code replay and refresh-token reuse** ("replay/resurrection" probes of single-use contracts), **PKCE downgrade** (S256 → `plain` transit secret), **state/nonce fixation** for login-CSRF and replayable `id_token`s, and **redirect_uri validator confusion**.

### Per-parameter encoding and canonicalization

In the TamperOauth tab every parameter row carries its own **Encoding** selector:

| Encoding | Effect |
| --- | --- |
| None | original value replayed byte-exact |
| Canonicalize | upper-cases percent-escape hex, folds `+` into `%20`, keeps the double-encoded outer layer |
| URL ×1 / ×2 / ×3 | percent-encode ladder |
| Base64 / Base64 URL | standard / URL-safe unpadded |
| ASCII Hex | lowercase hex of UTF-8 bytes |
| Overlong UTF-8 | metacharacters recast as two-byte overlong sequences |

"None" is genuinely byte-exact: `Param` stores the original raw wire bytes and replays them verbatim whenever the value is unchanged (or re-encodes only the characters that would corrupt the query envelope — `& # % space` and control bytes — keeping `/ : @ = + , ; ! $ ' ( ) * - . _ ~` intact). Encodings are applied per parameter name *at technique-build time*, so a single run can mix encoded and unencoded parameters.

## The UI

Hacktor registers a work panel under **Tools → Hacktor…** (and right-click → **Send to Hacktor** from the Sites tree, History or Search). It is a single tabbed panel with six tabs — **Target, TamperOauth, Techniques, Results, Log, Advanced** — plus ZAP Request/Response viewers embedded in the Results tab for inspecting stored probe messages.

### The Target tab

The main console: a target URL field with **From Selected**, a **Fetch Baseline** button (reports `Baseline: <status> (<bytes> bytes)`, green-turning-orange when the baseline is an error page), and the probe options — **Follow Redirects**, **Suppress Custom Error Pages**, **Stop on first Candidate**, **Retry on network error**, **Raw wire for ambiguous requests**, and **Exp. backoff on 403/429 flag**. The **Fuzz Mode** expander turns the panel into a generic request fuzzer: a wordlist drives one request per word against the URL (REPLACE/APPEND/PREPEND), custom header rules (per-rule `find` string replaced by each word; blank = `FUZZ`), and a JSON/XML body editor ("Format", "Add FUZZ", "Load from Base") with REPLACE/APPEND/PREPEND body modes. The **Out-of-Band Callbacks** section stores your callback URL persistently.

### The TamperOauth tab

A paste-a-URL OAuth lab: **Detect** parses the URL and shows the endpoint and flow; **From Selected** reuses a selected message; an editable **Parameters & Values** table (Name / Value / Source `query`|`body` / Encoding) with Add/Remove; tier checkboxes **Classic / Rare / Novel** with a live technique count; and the OAuth run controls (**Run OAuth Run**, **Stop**) sharing all the global probe knobs.

### The Techniques tab

The full catalogue as a five-column table (**On / Category / Technique / Tier / Description**), filtered by injection class, free-text across All/Label/Family/Description, plus "Custom only". A per-family checkbox strip at the top toggles whole families and shows live enabled counts. The row buttons **Add Custom**, **Duplicate**, **Edit**, **Remove** manage the catalogue, and **Enable All / Disable All / Invert** sweep it. Technique toggles survive rebuilds (persisted to `hacktor.famOn/.famOff/.rowsOn/.rowsOff`).

### The Results tab

Each probe is one row — **# / Category / Technique / Path / Status / Length / Base / Verdict / Req ms / Res ms** — filterable by text and by **Candidates only** / **Errors only**, and sortable so `CANDIDATE` verdicts float to the top. Selecting a row loads its stored request/response into the embedded ZAP viewers. Summary line `Candidates: N | Suppressed: N | Changes: N | Probes: N in <s>s`. Actions: **Export CSV**, **Resend** (re-send a probe and refresh its status), **Copy URL**, **Copy as cURL**, **Clear**. Non-candidate rows are pruned oldest-first when the retention cap (default 10 000) is reached, so candidate request/response detail is preserved.

### The Log tab

A live, tail-truncated scan log (cap default 500 KB) with `[*]`, `[!]`, `[+]`, `[-]`, `[~]` prefixes, candidate lines like `[!] CANDIDATE: <technique> -> 200 (8124 bytes)`, and a completion summary naming how many `CANDIDATE BYPASSE(S) FOUND`.

### The Advanced tab

The **Injection Tier Gate** (Classic/Rare/Novel checkboxes; unchecked tiers are rebuilt disabled), editable **fixed request headers** sent with every probe *and* the baseline (persisted as `hacktor.fixedheaders`), the **Memory Retention** caps (max results, log cap), and an info line for the advanced families (Raw Aberrations, Scheme Tampering, header confusion Host/`:authority`, obs-fold).

### Dialogs and context menu

- **Custom technique dialog** — Name/Category/Description plus a Type switch: *Path Replacement*, *Header Override*, or *Placement Probe* (vuln class + one of the 8 placements + payload, with a per-technique encode dropdown). Editing a built-in technique first asks to convert it into an editable custom copy.
- **Add Header Rule / Add Fixed Header dialogs** — name, optional find-string, SET/APPEND/PREPEND mode.
- **Right-click ("Send to Hacktor")** — available from Sites tree, History and Search, clones the request into the Target tab, rebuilds the technique set against it and auto-detects OAuth URLs.

## Run controls and shared knobs

| Control | Default | Meaning |
| --- | --- | --- |
| From Selected / Fetch Baseline | — | load a message from the Sites tree / fetch the baseline once |
| Follow Redirects | on | follow redirects for baseline and probes |
| Suppress Custom Error Pages | on | treat 2xx/3xx/404 bodies that look like branded error pages as suppressed |
| Stop on first Candidate | off | abort the run at the first `CANDIDATE` verdict |
| Retry on network error | off | re-send a probe (up to 3 attempts) on network-level failure |
| Raw wire for ambiguous requests | on | force raw-socket sending so exact bytes reach the server (auto-falls back) |
| Exp. backoff on 403/429 flag | off | exponential backoff (1s → 30s) while the server flags probes, halving back down on clean responses |
| Rate Limit (req/sec) | 0 | 0 = unlimited |
| Threads | 1 | 1 = serial (order-preserving); up to 16 |
| Timeout (sec) | 5 | per-probe socket timeout |
| Max Probes | 0 | 0 = all; caps fuzz words otherwise |
| Tier gates (Classic/Rare/Novel) | on | unchecked tiers are rebuilt disabled |
| Max results / Log cap | 10000 rows / 500 KB | retention caps, pruning oldest non-candidates first |

Live status: `Probes: N | Candidates: N | Elapsed: M:SS`, a string-painted progress bar, and Pause/Resume/Stop controls.

## ZAP integration

- **Work panel** — hooked as a ZAP work panel (`Toolbar`/tabs) plus **Tools → Hacktor…** menu entry.
- **Context menu** — *Send to Hacktor* is registered on the Sites tree, History and Search message containers, weight 25070, safe for headless use.
- **Persisted options** — general settings under `hacktor.settings` (key=value), OOB URL under `hacktor.oobUrl`, custom and fixed headers under `hacktor.headers` / `hacktor.fixedheaders`, technique toggles under `hacktor.famOn/.famOff/.rowsOn/.rowsOff`.
- **No History pollution from probing** — the add-on sends via its own `HttpSender` (initiator `MANUAL_REQUEST_INITIATOR`); raw-wire probes never transit ZAP's request pipeline. The internal `X-Hacktor-WirePath` / `X-Hacktor-Timing` side-channel headers are stripped before any message is stored, shown or exported.
- **Unloadable** — `canUnload()` is true; unload unregisters the viewers and panel state.

## Requirements

- **ZAP 2.17.0** or later.
- **Java 17** or later.
- **RSyntaxTextArea** runtime jar (for the JSON/XML body editor) — bundled in the ZAP distribution next to `zap-2.17.0.jar`.

No other ZAP add-on is required. Burp Collaborator / Interactsh / Canarytokens are optional: they power the out-of-band callback probes when a callback URL is configured.

## Build

Requires JDK 17+ and the ZAP jar on disk. Two equivalent paths:

```bash
# build.sh (zero-dependency path) — expects
ZAP_JAR=/opt/ZAP_2.17.0/zap-2.17.0.jar
RSYNTAX_JAR=/opt/ZAP_2.17.0/lib/rsyntaxtextarea-3.6.0.jar
./build.sh
# -> build/dist/hacktor-alpha-1.0.0.zap
```

```bash
# or with Gradle (ZAP-standard build)
gradle packageRaw
```

The `.zap` artifact is a plain ZIP of the compiled add-on directory.

## Install in ZAP

1. Build the `.zap` (above) or download `hacktor-alpha-1.0.0.zap`.
2. In ZAP: **Manage Add-ons** (toolbar) → **Install local add-on…** → select the `.zap` file.
3. Open **Tools → Hacktor…** (or right-click any message in Sites/History → **Send to Hacktor**).

## Usage

1. Right-click a request in the Sites tree, History or Search → **Send to Hacktor**, or type/paste a target URL in the Target tab.
2. **Fetch Baseline** (or let the run do it automatically) — the baseline status/length is the yardstick every probe is measured against.
3. On the Techniques tab, prune as desired — uncheck a tier gate on the Advanced tab, toggle families, disable noisy rows. Configure an OOB **Callback URL** on the Target tab if you want command-execution/XXE/SSRF evidence.
4. Hit **Run**. Watch the Log tab and the live stats; the run pauses/resumes/stops cleanly and honors the rate limit, threads and backoff knobs.
5. Click into the Results tab — sort by Verdict, filter **Candidates only**, inspect full messages in the embedded viewers, **Resend** anything, or **Copy as cURL** to re-run a probe outside ZAP.
6. Tune the catalogue: **Add Custom** a path/header/placement technique, Duplicate and edit built-ins as editable copies, then Export **CSV** for your notes.
7. For OAuth: paste an authorization/token URL into **TamperOauth**, hit **Detect**, and run the 122-technique catalogue; per-parameter encodings let you attack one value with one encoding while others stay byte-exact.

A typical "does this 401 turn into a 200?" flow:

```
right-click /admin/panel  ->  Send to Hacktor
Fetch Baseline            ->  401 (1234 bytes)
Run  (Classic+Rare+Novel, rate-limited)
Results: sort by Verdict  ->  scan CANDIDATE rows
Copy as cURL on the winner ->  manual confirmation
```

## Behaviour notes

- **Counts are per-target**: the 7800+ figure is the product of catalogue × placements × segments × tiers × encodings × body params × OOB — not a fixed list, so a small API endpoint generates fewer, a deep multi-segment path generates more.
- **Fuzzing is one mutation at a time**: each probe varies exactly one dimension of the request (with custom header rules and body modes applied deterministically), so a verdict is attributable to a single change.
- **Baseline-or-vs-probe**: candidates are defined by *deviation from the baseline*, so a target whose 403 already renders a 200 banner still yields clean candidates on real differences.
- **Error-page suppression is unconditional**: the marker-regex + ±12% length heuristic runs before options, so branded "access denied" banners don't pollute results even with suppression toggled.
- **Raw sending is best-effort and reversible**: `RawHttpSender` returns `false` on any failure and the engine silently falls back to ZAP's standard sender — raw-only techniques degrade, never die.
- **Probe traffic is yours**: normal probes go through ZAP's sender (so they appear in History), raw-wire probes bypass it. Nothing is ever sent to a target from passive analysis — Hacktor only ever re-fires the request you author.
- **OAuth variants keep the wire honest**: unchanged parameter values are replayed byte-exact, and the exact wire target (including literal fragments) is enforced via the raw path.

## Security notes

- Hacktor is an **active** testing tool — every Run sends live requests to the target. Use it only against systems you are authorized to test, and keep the rate limit, threads and backoff knobs sensible for your target.
- **Out-of-band probes are opt-in**: no callback URL is configured by default, and OOB techniques are only generated once one is saved.
- Verdicts are a **research aid, not proof**: a candidate means "response deviated from baseline in a way typically associated with bypass" — confirm with Resend / Copy as cURL and manual review before reporting a finding.
- The **value masking** used in the OAuth/technique UIs and CSV export mirrors what you see; the raw values remain in the request data exactly as ZAP normally holds them.
- Fuzz Mode with a large wordlist equals a large number of requests: bound it with **Max Probes** and the wordlist size.

---

## Development

```
src/main/java/org/zaproxy/zap/extension/hacktor/
  ExtensionHacktor.java                  entry point (work panel, Tools menu, popup hook)
  HacktorPanel.java                      the six-tab UI (Target/TamperOauth/Techniques/Results/Log/Advanced)
  HacktorEngine.java                     mutation pipeline: build → tier gate → run → verdict
  RawHttpSender.java                     minimal raw-socket sender (verbatim request head + target)
  OauthEngine.java                       the OAuth 1.0a/2.0/OIDC tamper lab (122 techniques)
  VulnCatalog.java                       23 injection classes · 308 payloads · 31 OOB templates · tiers
  Technique.java                         one atomic mutation (family, label, tier, needsRawWire, apply)
  Result.java                            probe outcome + stored HttpMessage
  PayloadEncoder.java                    Recode-style encoders (URL×1/2/3, B64, B64U, Hex, HTML, overlong UTF-8)
  BodyParams.java                        body extraction (form/multipart/JSON/XML) + span-accurate rewrite
  PopupMenuSendToBypass.java             "Send to Hacktor" message-container popup
  technique/
    <40+ TechniqueBuilder classes>       per-family generators (Fragment, Request Smuggling, Raw
                                         Aberrations, WAF ladders, cache poisoning, …)
src/main/resources/org/zaproxy/zap/extension/hacktor/
  Messages.properties                    i18n bundle (prefix: hacktor)
ZapAddOn.xml                             add-on manifest (name, version, status, extension)
build.gradle.kts · settings.gradle.kts   org.zaproxy.add-on plugin build (Java 17, ZAP 2.17.0)
build.sh                                 zero-dependency build → build/dist/hacktor-alpha-1.0.0.zap
```

The engine is deliberately flat per probe — each `Technique` carries a compiled `apply(HttpMessage)` mutation and a `needsRawWire` flag, so the same technique list powers the threaded runner, the raw-wire fallback, and the OAuth lab. The catalogue (`VulnCatalog`) is data: family, default header, query key, tiered payloads and OOB templates, consumed by a shared placement engine in eight kinds, so adding a new injection class or a new technique family is additive.

## Credits

- Design and implementation: **ArkhaMahn** — [github.com/ArkhaMahn/Hacktor](https://github.com/ArkhaMahn/Hacktor).
- Payload inspiration from the ProjectDiscovery [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository and common public bypass sets.
- Encoding transforms mirror the **Recode** ZAP add-on's encode/decode/hash/convert ladder.
- Companion ZAP work: **GhostJS** — [github.com/ArkhaMahn/zap-ghostjs](https://github.com/ArkhaMahn/zap-ghostjs).

## License

[MIT](/ArkhaMahn/Hacktor/blob/main/LICENSE) © 2026 ArkhaMahn