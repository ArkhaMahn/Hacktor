package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.apache.commons.httpclient.URI;
import java.util.List;
import java.util.function.BiConsumer;

public abstract class AbstractTechniqueBuilder implements TechniqueBuilder {

    protected static void addHeader(HttpMessage msg, String name, String value) {
        try { msg.getRequestHeader().setHeader(name, value); } catch (Exception ignored) {}
    }

    protected static void removeHeader(HttpMessage msg, String name) {
        try { msg.getRequestHeader().setHeader(name, null); } catch (Exception ignored) {}
    }

    protected static void setMethod(HttpMessage msg, String method) {
        try { msg.getRequestHeader().setMethod(method); } catch (Exception ignored) {}
    }

    protected static void setHTTPVersion(HttpMessage msg, String version) {
        try { msg.getRequestHeader().setVersion(version); } catch (Exception ignored) {}
    }

    protected static String currentPath(HttpMessage msg) {
        try {
            URI uri = msg.getRequestHeader().getURI();
            if (uri == null) return "";
            String p = uri.getPath();
            if (p == null) p = "";
            String q = uri.getQuery();
            if (q != null && !q.isEmpty()) p = p + "?" + q;
            return p;
        } catch (Exception e) { return ""; }
    }

    /**
     * Sets the request-target to an exact literal string on the wire, bypassing the
     * URI class' re-encoding. Use for paths containing raw %XX sequences (Padding),
     * backslashes (Backslash Path, UNC), or other characters that URI.setPath would
     * re-encode. The literal value is also shown in the Path column of the Results tab.
     */
    protected static void setLiteralPath(HttpMessage msg, String literalPath) {
        try {
            // Prepend '/' to form valid HTTP origin-form when the path doesn't start
            // with a recognized form: '/' (origin-form), '*' (asterisk-form), '\\'
            // (Windows single-backslash path), '\\\\' (UNC prefix), "//?/" (device path).
            String wirePath = literalPath;
            if (!wirePath.startsWith("/") && !wirePath.startsWith("*")
                && !wirePath.startsWith("\\") && !wirePath.startsWith("//?/")) {
                wirePath = "/" + wirePath;
            }
            msg.getRequestHeader().setHeader("X-Hacktor-WirePath", wirePath);
        } catch (Exception ignored) {}
    }

    protected static void replacePath(HttpMessage msg, String path) {
        try {
            URI uri = msg.getRequestHeader().getURI();
            if (uri == null) return;

            int hashIdx = path.indexOf('#');
            if (hashIdx >= 0) path = path.substring(0, hashIdx);
            int qi = path.indexOf('?');
            String pathPart = qi >= 0 ? path.substring(0, qi) : path;
            String queryPart = qi >= 0 ? path.substring(qi + 1) : null;

            // Absolute-form input (e.g. "http://[::1]/admin/panel"): store the literal
            // string as the URI's path. uri.getPath() preserves brackets as-is, and the
            // raw sender recognises the "://" marker on the unescaped path and uses
            // the literal form as the request-target. The URI's host stays the original
            // (this is intentional — the bypass probe tests how the server reacts to a
            // request-target with a different host).
            if (pathPart.indexOf("://") > 0) {
                uri.setPath(pathPart);
                if (queryPart != null) uri.setQuery(queryPart);
                return;
            }

            // Ensure the path starts with '/' (HTTP origin-form).
            if (!pathPart.startsWith("/")) pathPart = "/" + pathPart;

            uri.setPath(pathPart);
            if (queryPart != null) uri.setQuery(queryPart);
        } catch (Exception ignored) {}
    }

    protected static void setPathWithFragment(HttpMessage msg, String pathWithFragment) {
        try {
            URI uri = msg.getRequestHeader().getURI();
            if (uri == null) return;
            int fragIdx = pathWithFragment.indexOf('#');
            String path;
            String frag;
            if (fragIdx >= 0) {
                path = pathWithFragment.substring(0, fragIdx);
                frag = pathWithFragment.substring(fragIdx + 1);
            } else {
                path = pathWithFragment;
                frag = null;
            }
            int qi = path.indexOf('?');
            String query = null;
            if (qi >= 0) {
                query = path.substring(qi + 1);
                path = path.substring(0, qi);
            }
            if (path == null || path.isEmpty() || path.charAt(0) != '/') {
                path = "/" + (path == null ? "" : path);
            }
            uri.setPath(path);
            if (query != null) uri.setQuery(query);
            if (frag != null) uri.setFragment(frag);
        } catch (Exception ignored) {}
    }

    protected static HttpMessage cloneMsg(HttpMessage base) {
        return base.cloneAll();
    }

    protected static String joinPath(String[] segments) {
        if (segments == null || segments.length == 0) return "/";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) sb.append("/");
            sb.append(segments[i]);
        }
        return sb.toString();
    }

    protected static String joinFromSegment(String[] segments, int start) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < segments.length; i++) {
            if (i > start) sb.append("/");
            sb.append(segments[i]);
        }
        return sb.toString();
    }

    protected static String[] append(String[] arr, String[] add) {
        String[] r = new String[arr.length + add.length];
        System.arraycopy(arr, 0, r, 0, arr.length);
        System.arraycopy(add, 0, r, arr.length, add.length);
        return r;
    }

    protected static String buildEncoded(String[] segments, int splitAt,
            boolean slashBeforeHash, boolean doubleEnc, String lastSeg) {
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

    protected static String toFullwidth(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= '!' && c <= '~') {
                sb.append((char) (c + 0xFEE0));
            } else if (c == ' ') {
                sb.append('\u3000');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Safe substring that never throws on short strings. */
    protected static String trunc(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen);
    }

    /**
     * Tags a technique as needing raw-wire transmission (fragment preservation,
     * malformed request line / verbs, HTTP/2 pseudo-headers, smuggling framing)
     * and returns it, so it can be used inline in {@code techs.add(...)}.
     */
    protected static Technique raw(Technique t) {
        t.setNeedsRawWire(true);
        return t;
    }

    /** Adds a technique to the list, marking it as needing raw-wire transmission. */
    protected static void markRawAdd(List<Technique> techs, Technique t) {
        t.setNeedsRawWire(true);
        techs.add(t);
    }
}
