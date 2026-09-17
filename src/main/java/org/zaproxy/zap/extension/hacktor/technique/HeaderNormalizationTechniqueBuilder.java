package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HeaderNormalizationTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Header Normalization"; }
    @Override public int getOrder() { return 28; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] headerCaseVariants = {
            {"X-Forwarded-For","127.0.0.1"},{"x-forwarded-for","127.0.0.1"},
            {"X-FORWARDED-FOR","127.0.0.1"},{"X-forwarded-for","127.0.0.1"},
            {"X-Forwarded-for","127.0.0.1"},{"x-Forwarded-For","127.0.0.1"},
            {"x-Forwarded-For","127.0.0.1"},{"X_fwd_for","127.0.0.1"},
            {"x-forwarded_for","127.0.0.1"},{"X-FORWARDED_FOR","127.0.0.1"},
            {"X-Real-IP","127.0.0.1"},{"x-real-ip","127.0.0.1"},
            {"X-REAL-IP","127.0.0.1"},{"X_Real_Ip","127.0.0.1"},
            {"Host","localhost"},{"host","localhost"},{"HOST","localhost"},
            {"Content-Type","application/json"},{"content-type","application/json"},
            {"Content-type","application/json"},{"content-Type","application/json"},
        };
        for (String[] hcv : headerCaseVariants) {
            final String hn = hcv[0], hv = hcv[1];
            techs.add(new Technique("Header Normalization", "HdrNorm:" + trunc(hn.replace("-", "").replace("_", "").replace(" ", ""), 12),
                "Case-varied header: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] underscoreHeaders = {
            {"X_Forwarded_For","127.0.0.1"},{"X_Real_IP","127.0.0.1"},
            {"X_Original_URL",ctx.baseClean},{"Content_Type","application/json"},
            {"Accept_Encoding","gzip, deflate"},{"Accept_Language","en-US,en;q=0.9"},
            {"X_HTTP_Method","GET"},{"X_HTTP_METHOD_OVERRIDE","POST"},
        };
        for (String[] uh : underscoreHeaders) {
            final String hn = uh[0], hv = uh[1];
            techs.add(new Technique("Header Normalization", "HdrUnderscore:" + uh[0].replace("_", "U"),
                "Underscore variant: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] foldedHeaders = {
            {"X Forwarded For","127.0.0.1"},{"X Real IP","127.0.0.1"},
            {"Content Type","application/json"},{"Accept Encoding","gzip"},
        };
        for (String[] fh : foldedHeaders) {
            final String hn = fh[0], hv = fh[1];
            techs.add(new Technique("Header Normalization", "HdrFolded:" + fh[0].replace(" ", "SPC"),
                "Space-in-name header: '" + hn + "': " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        techs.add(new Technique("Header Normalization", "HdrTab:XFF",
            "Tab in header name: X-Forwarded-For\\t",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "X-Forwarded-For\t", "127.0.0.1"); return c; }));
        techs.add(new Technique("Header Normalization", "HdrTab:Host",
            "Tab in header name: Host\\t",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Host\t", "localhost"); return c; }));

        techs.add(new Technique("Header Normalization", "HdrDualHost",
            "Dual Host headers: localhost + 127.0.0.1",
            base -> { HttpMessage c = cloneMsg(base);
                addHeader(c, "Host", "localhost"); addHeader(c, "host", "127.0.0.1"); return c; }));

        String[][] colonHeaders = {{"X-Forwarded:For","127.0.0.1"},{"Host:Internal","localhost"}};
        for (String[] ch : colonHeaders) {
            final String hn = ch[0], hv = ch[1];
            techs.add(new Technique("Header Normalization", "HdrColon:" + trunc(ch[0].replace(":", "COL").replace("-", ""), 15),
                "Colon in header name: '" + hn + "': " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        StringBuilder longName = new StringBuilder("X-A");
        for (int i = 0; i < 10; i++) longName.append("-Long-Header-Name");
        longName.append("-Suffix");
        final String longHeaderName = longName.toString();
        String[][] longHeaders = {
            {"X-Custom-Header-A-With-A-Very-Long-Name-That-May-Be-Truncated-By-Some-WAFs","value"},
            {longHeaderName,"value"},
        };
        for (String[] lh : longHeaders) {
            final String hn = lh[0], hv = lh[1];
            techs.add(new Technique("Header Normalization", "HdrLong:" + trunc(hn, 15).replace("-", "D"),
                "Long header name: " + trunc(hn, 30) + "...",
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
