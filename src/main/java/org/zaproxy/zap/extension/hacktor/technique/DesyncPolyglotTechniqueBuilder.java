package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The 0-Content-Length probe payloads from PortSwigger's <em>http-terminator</em>
 * validator ({@code validator/src/main/java/burp/ProbePayloads.java}).
 *
 * <p>Each payload is a complete HTTP request or request fragment. It is placed in
 * a request whose {@code Content-Length} is <b>zero</b> and is also mirrored into
 * a header value, so the same bytes exist in two places a parser can disagree
 * about:
 *
 * <ul>
 *   <li>a front end that honours {@code Content-Length: 0} reads no body, and
 *       whatever follows on the connection becomes the next request;</li>
 *   <li>an origin that reads the body (or the {@code A:} header) executes the
 *       smuggled request;</li>
 *   <li>a server that rejects {@code TRACE}, or a proxy that normalises it, forks
 *       the pipeline at a different point again.</li>
 * </ul>
 *
 * <p>The payloads themselves are the discriminating part — a raw {@code X}, a
 * {@code CONNECT} to a collaborator host, a request with no body at all — and
 * they are reproduced here byte for byte.
 *
 * <p><b>Deviation from upstream.</b> http-terminator also pads the {@code A:}
 * header value so that the payload's byte offset inside the header block lines up
 * with the declared body length, which lets its canary correlator confirm a
 * desync at a known offset. Hacktor reports "the response changed" rather than
 * correlating canaries, so the padding arithmetic is omitted; the payload
 * placement and the {@code Content-Length: 0} framing — the part that actually
 * makes the two parsers disagree — are unchanged.
 */
public class DesyncPolyglotTechniqueBuilder extends DesyncTechniqueBuilder {

    @Override public String getFamily() { return "Desync Polyglot"; }
    @Override public int getOrder() { return 68; }

    @Override public Technique.Position getPosition() { return Technique.Position.REQUEST; }


    private static final String FAMILY = "Desync Polyglot";

    /**
     * {@code id}, payload body, and whether it may be used in the 0-CL header
     * form. The third column is upstream's {@code supports0CL}, which is true for
     * every payload declared through the three-argument constructor (ids 0 and
     * 2-8) and false for the four explicitly non-0-CL ones (1 and 9-12).
     */
    private static final String[][] PAYLOADS = {
        // Default probe: a full second request, smuggled verbatim.
        {"0", "TRACE /asdf HTTP/1.1\r\nA: B", "true", "full request line in the body"},
        {"1", "X", "false", "single opaque byte"},
        {"2", "GET / HTTP/1.1\r\nX: Y", "true", "GET with headers"},
        {"3", "GET /favicon.ico HTTP/1.1\r\nX: Y", "true", "GET of a static file"},
        {"4", "GET /asdf HTTP/1.1\r\nX: Y", "true", "GET of a random path"},
        {"5", "GET /0-9 HTTP/0.9\r\nX: Y", "true", "HTTP/0.9 request line"},
        {"6", "GET /invalid HTTP/1.2\r\nX: Y", "true", "invalid HTTP version"},
        {"7", "TRACE / HTTP/1.1\r\nX: Y", "true", "TRACE verb"},
        {"8", "GET /%2f HTTP/1.1\r\nX: Y", "true", "encoded slash in the target"},
        {"9", "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nx=1",
                "false", "POST with its own CL inside a 0-CL request"},
        {"10", "GET /?rqp HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                "false", "GET with an unknown query parameter"},
        {"11", "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nX: Y",
                "false", "two pipelined GETs"},
        {"12", "CONNECT n1p4fbvwvalvyvljgp8a3zts4jaay5mu.psres.net:443\r\n"
                + "Host: ob35pc5x5bvw8wvkqqibd03tekkb85wu.psres.net\r\n\r\n",
                "false", "CONNECT tunnel to a collaborator host"},
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        final String baseClean = ctx.baseClean;
        for (String[] row : PAYLOADS) {
            final String id = row[0];
            final String payload = row[1];
            final boolean supports0CL = Boolean.parseBoolean(row[2]);
            final String what = row[3];
            final boolean mirror = supports0CL;

            Technique tech = new Technique(FAMILY, "Poly" + id + ":ZeroCL",
                "Content-Length: 0 with a " + what + " body"
                    + (mirror ? ", mirrored into an 'A:' header" : ""),
                base -> {
                    HttpMessage c = cloneMsg(base);
                    setMethod(c, "POST");
                    if (mirror) {
                        // Upstream inserts "A: B<payload>" immediately after the
                        // request line. ZAP's header model would reorder it and
                        // split the payload's own CRLF into a continuation line, so
                        // it travels as a raw wire header line instead.
                        addWireHeaderLines(c, "A: B" + payload);
                    }
                    applyRaw(c, null, null, payload, Framing.CL0);
                    return c;
                });
            tech.setTier(supports0CL ? VulnCatalog.Tier.CLASSIC : VulnCatalog.Tier.RARE);
            // A 0-CL probe that the front end refuses to parse, or that comes back
            // with no body at all, tells us nothing about a desync.
            tech.setDiscardOn(400, 404);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }

        // The same payload set framed the other way round: no Content-Length at
        // all, so the body is framed by connection close. A front end that
        // requires a framing header and one that does not disagree here.
        for (String[] row : PAYLOADS) {
            final String id = row[0];
            final String payload = row[1];
            Technique tech = new Technique(FAMILY, "Poly" + id + ":EOF",
                "no Content-Length and no Transfer-Encoding - body framed by "
                    + "connection close",
                base -> {
                    HttpMessage c = cloneMsg(base);
                    setMethod(c, "POST");
                    applyRaw(c, null, null, payload, Framing.EOF);
                    return c;
                });
            tech.setTier(VulnCatalog.Tier.NOVEL);
            tech.setDiscardOn(400, 404);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }
    }
}
