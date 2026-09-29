package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;

/**
 * Shared plumbing for the request-smuggling / response-desynchronisation families
 * ported from PortSwigger's <em>http-terminator</em> research pipeline.
 *
 * <p>Every technique in those corpora is a <em>whole request</em>: a specific
 * combination of request line, header block and body bytes that makes two HTTP
 * parsers disagree about where one request ends and the next begins. Expressing
 * them as data (rather than as a chain of {@code addHeader} calls) is what keeps
 * the port faithful — the byte-level framing is the technique, so it has to be
 * expressible in one place.
 *
 * <p>Every probe here is raw-wire. The whole point of these requests is to put
 * bytes on the socket that ZAP's {@code HttpSender} would normalise away: bare
 * LF line endings, chunk sizes with extensions or {@code 0x} prefixes, bodies
 * that contradict their own {@code Content-Length}, and request lines that are
 * not request lines at all.
 */
public abstract class DesyncTechniqueBuilder extends AbstractTechniqueBuilder {

    /** How the body is framed once a probe has written its bytes. */
    protected enum Framing {
        /** {@code Content-Length} matches the body length. */
        CL,
        /** {@code Content-Length: 0} with a body still attached (the 0-CL polyglot). */
        CL0,
        /** {@code Transfer-Encoding: chunked}; the caller supplies pre-framed chunks. */
        CHUNKED,
        /** No body and no {@code Content-Length} at all — framed by connection close. */
        EOF,
        /**
         * The body is written but the framing headers are left exactly as the
         * caller set them. Used where the <em>declared</em> length is the probe:
         * a signed {@code Content-Length: +5}, one with extra optional
         * whitespace, or a duplicate pair of contradictory values. Any other mode
         * would replace them with a correct computed length and the probe would
         * degenerate into an ordinary POST.
         */
        AS_DECLARED
    }

    /**
     * Rewrites {@code msg} into a complete raw request.
     *
     * @param method  request method, or {@code null} to keep the base method
     * @param headers header name/value pairs to apply, or {@code null} for none
     * @param body    raw body bytes, or {@code null} for none
     * @param framing how {@code body} is to be framed
     */
    protected static void applyRaw(HttpMessage msg, String method, String[][] headers,
                                   String body, Framing framing) {
        if (method != null) setMethod(msg, method);
        if (headers != null) {
            for (String[] h : headers) {
                if (h == null || h.length < 2) continue;
                if (h[1] == null) removeHeader(msg, h[0]);
                else if (WIRE_HEADER_LINES.equalsIgnoreCase(h[0])) addWireHeaderLines(msg, h[1]);
                else addHeader(msg, h[0], h[1]);
            }
        }
        try {
            switch (framing) {
                case CL:
                    msg.getRequestBody().setBody(body == null ? "" : body);
                    addHeader(msg, "Content-Length", String.valueOf(lenOf(body)));
                    break;
                case CL0:
                    // The body stays on the message but the framing header claims
                    // zero bytes: a front end that honours CL reads nothing and the
                    // next request on the connection starts at the body.
                    msg.getRequestBody().setBody(body == null ? "" : body);
                    addHeader(msg, "Content-Length", "0");
                    break;
                case CHUNKED:
                    removeHeader(msg, "Content-Length");
                    addHeader(msg, "Transfer-Encoding", "chunked");
                    msg.getRequestBody().setBody(body == null ? "" : body);
                    break;
                case EOF:
                    removeHeader(msg, "Content-Length");
                    removeHeader(msg, "Transfer-Encoding");
                    msg.getRequestBody().setBody(body == null ? "" : body);
                    break;
                case AS_DECLARED:
                    // Deliberately do not touch Content-Length or Transfer-Encoding:
                    // whatever the caller declared is the probe.
                    msg.getRequestBody().setBody(body == null ? "" : body);
                    break;
            }
        } catch (Exception ignored) {
            // Best effort: a body ZAP refuses to store still leaves a mutated request.
        }
    }

    /**
     * Appends a header line without replacing an existing one of the same name.
     * {@code AbstractTechniqueBuilder.addHeader} is really a set (it delegates to
     * {@code setHeader}), so duplicate framing headers need this instead.
     */
    protected static void appendHeader(HttpMessage msg, String name, String value) {
        try { msg.getRequestHeader().addHeader(name, value); } catch (Exception ignored) {}
    }

    /** Length of a body in bytes, treating {@code null} as empty. */
    protected static int lenOf(String body) {
        if (body == null) return 0;
        try {
            return body.getBytes("ISO-8859-1").length;
        } catch (Exception e) {
            return body.length();
        }
    }

    /**
     * A fixed, harmless request used to fill the smuggled-request slot in the
     * upstream corpus (their {@code $payload} placeholder). It asks for the
     * target's own path with a marker query parameter, so a desync shows up as a
     * second hit on that path rather than as traffic to somewhere unexpected.
     */
    protected static String smuggledRequest(String baseClean) {
        String p = (baseClean == null || baseClean.isEmpty()) ? "/" : baseClean;
        return "GET " + p + "?smuggled=1 HTTP/1.1\r\nHost: localhost\r\nX-Hacktor-Smuggled: 1\r\n\r\n";
    }

    /** Replaces the corpus's {@code $payload} marker with a real smuggled request. */
    protected static String withSmuggled(String template, String baseClean) {
        return template.replace("$payload", smuggledRequest(baseClean));
    }
}
