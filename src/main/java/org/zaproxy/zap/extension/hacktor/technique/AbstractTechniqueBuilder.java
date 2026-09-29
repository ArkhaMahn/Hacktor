package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.apache.commons.httpclient.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public abstract class AbstractTechniqueBuilder implements TechniqueBuilder {

    /**
     * The request surface this builder's techniques target. Left null by default:
     * a builder that emits a single kind of probe should override it, and a mixed
     * builder should stamp each technique in {@link #build} instead.
     */
    @Override public Technique.Position getPosition() { return null; }

    /** Pseudo-header used to hand an exact request-target to the raw sender. */
    protected static final String WIRE_PATH = "X-Hacktor-WirePath";

    /** Pseudo-header used to hand exact, possibly malformed header lines to the raw sender. */
    protected static final String WIRE_HEADER_LINES = "X-Hacktor-WireHeaderLines";

    /** Pseudo-header used to hand a complete, exact request line to the raw sender. */
    protected static final String WIRE_REQUEST_LINE = "X-Hacktor-WireRequestLine";

    /**
     * Emits {@code line} as the whole request line, byte for byte, instead of the
     * {@code method SP target SP version} triple the header model would build.
     *
     * <p>{@link org.parosproxy.paros.network.HttpRequestHeader#setVersion} upper-cases
     * the version field, so a status line used as a request line comes back out as
     * {@code HTTP/1.1 100 CONTINUE} instead of {@code HTTP/1.1 100 Continue}. The
     * reason phrase is part of the probe — a front end and a back end that disagree
     * about it disagree about tokenisation — so it has to survive verbatim. The
     * tokenised form is still stored on the message, so the request viewer shows how
     * a parser sees the line; only the bytes on the wire are forced.
     */
    protected static void setWireRequestLine(HttpMessage msg, String line) {
        if (line == null || line.isEmpty()) return;
        try { msg.getRequestHeader().setHeader(WIRE_REQUEST_LINE, line); } catch (Exception ignored) {}
    }

    /**
     * Emits {@code lines} at the top of the request's header block, byte for byte.
     *
     * <p>{@code HttpRequestHeader} cannot represent a line that is not a
     * {@code name: value} pair: {@code setHeader("x ", null)} is rewritten to
     * {@code x : } on serialisation, and a value containing a raw CRLF is split
     * into continuation lines. Probes whose whole point is that malformation (a
     * bare token header, an obs-fold carrying a framing header) have to travel
     * out of band, so the raw sender prepends them and strips the marker.
     *
     * <p>The lines are stashed NUL-joined in a single pseudo-header rather than
     * verbatim, because the sender strips the marker by line prefix: a raw CRLF
     * in the value would leave the continuation lines behind after the strip.
     * {@code lines} is written as-is at send time, with {@code \r\n} between
     * entries, so the caller supplies the exact bytes of each line.
     */
    protected static void addWireHeaderLines(HttpMessage msg, String lines) {
        if (lines == null || lines.isEmpty()) return;
        try {
            // Normalise every line break in the payload to the separator so the
            // marker always occupies exactly one header line. ZAP splits a header
            // value on a raw CRLF, and the sender strips the marker by line prefix,
            // so a value carrying its own CRLF would leave its tail on the wire.
            // The sender maps the separator back to CRLF, so bytes round-trip.
            StringBuilder packed = new StringBuilder(lines.length() + 8);
            for (int i = 0; i < lines.length(); i++) {
                char ch = lines.charAt(i);
                if (ch == '\r' || ch == '\n') {
                    packed.append(WIRE_LINE_SEP);
                    if (ch == '\r' && i + 1 < lines.length() && lines.charAt(i + 1) == '\n') {
                        i++;
                    }
                } else {
                    packed.append(ch);
                }
            }
            String existing = msg.getRequestHeader().getHeader(WIRE_HEADER_LINES);
            String combined = (existing == null || existing.isEmpty())
                ? packed.toString() : existing + WIRE_LINE_SEP + packed;
            msg.getRequestHeader().setHeader(WIRE_HEADER_LINES, combined);
        } catch (Exception ignored) {}
    }

    /**
     * Separator used to pack multiple raw header lines into one pseudo-header. A
     * NUL is used because ZAP's header model round-trips it verbatim inside a
     * value, keeping the marker a single well-formed header line until it is
     * stripped at send time.
     */
    protected static final char WIRE_LINE_SEP = '\u0000';

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
            msg.getRequestHeader().setHeader(WIRE_PATH, wirePath);
        } catch (Exception ignored) {}
    }

    /**
     * Sets the request-target to an exact literal string on the wire, WITHOUT the
     * leading-slash normalisation applied by {@link #setLiteralPath}.
     *
     * <p>Character- and payload-sweep probes that prepend to the path ("{@code ;}",
     * "{@code ;admin}", "{@code \admin}", "{@code \x01}") produce a
     * <em>non-origin-form</em> request-target. That is a legitimate differential — a
     * lenient front end and a strict origin can disagree about what the path is — but it
     * is not a target a {@code URI} or ZAP's request-header setters will accept, so it
     * has to travel as a raw wire path.
     */
    protected static void setVerbatimWirePath(HttpMessage msg, String literalTarget) {
        try {
            msg.getRequestHeader().setHeader(WIRE_PATH, literalTarget == null ? "" : literalTarget);
        } catch (Exception ignored) {
            // The header API can reject values a URI parser dislikes; nothing else to do.
        }
    }

    /**
     * Sets the request-target literally, using the verbatim raw-wire path when the
     * result is not a valid origin-form target (no leading slash, not asterisk-form or
     * backslash/UNC form) and the normal {@link #setLiteralPath} otherwise.
     */
    protected static void setTarget(HttpMessage msg, String literalTarget) {
        if (literalTarget == null || literalTarget.isEmpty() || literalTarget.charAt(0) == '/') {
            setLiteralPath(msg, literalTarget);
        } else {
            setVerbatimWirePath(msg, literalTarget);
        }
    }

    /**
     * Removes every request header, leaving a bare request line (plus whatever body the
     * message already carried).
     *
     * <p>Ported from the 403 Bypasser's "downgraded HTTP and no headers" probe, which
     * rebuilds a request from nothing but the verb, the path and {@code HTTP/1.0}. Stacks
     * that take the authority from a {@code Host} header have nothing left to match
     * against, and an HTTP/1.0 client is not entitled to the features (keep-alive,
     * chunked transfer) a stricter guard may have been relying on.
     */
    protected static void stripAllHeaders(HttpMessage msg) {
        try {
            // Copy first: setHeader(name, null) mutates the collection we would iterate.
            for (HttpHeaderField field : new ArrayList<>(msg.getRequestHeader().getHeaders())) {
                msg.getRequestHeader().setHeader(field.getName(), null);
            }
        } catch (Exception ignored) {
            // Best effort: a header that refuses to be removed is still a probe.
        }
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

    /**
     * Adds a technique with an explicit payload position.
     *
     * <p>For a builder whose techniques do not all target the same surface — one
     * that writes both headers and query parameters, say — the family-level
     * {@link #getPosition()} is left null and every technique is stamped here, so
     * the position filter can separate them.
     */
    protected static void at(List<Technique> techs, Technique.Position pos, Technique t) {
        t.setPosition(pos);
        techs.add(t);
    }

    /** As {@link #at} but also marks the technique as needing raw-wire transmission. */
    protected static void atRaw(List<Technique> techs, Technique.Position pos, Technique t) {
        t.setPosition(pos);
        markRawAdd(techs, t);
    }
}
