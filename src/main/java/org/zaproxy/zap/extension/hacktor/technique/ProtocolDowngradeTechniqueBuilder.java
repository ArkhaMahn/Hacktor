package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class ProtocolDowngradeTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Protocol Downgrade"; }
    @Override public int getOrder() { return 23; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] downgradeHeaders = {
            {"X-Forwarded-Proto","http"},{"X-Forwarded-Proto","HTTP"},
            {"X-Forwarded-Protocol","http"},{"Front-End-Https","on"},
            {"Front-End-Https","yes"},{"X-Url-Scheme","http"},{"X-Url-Scheme","HTTP"},
            {"X-Original-Scheme","http"},{"X-Scheme","http"},
            {"X-Forwarded-Proto","https"},{"X-Forwarded-Proto","HTTP/1.0"},
            {"X-Forwarded-Proto","HTTP/1.1"},{"X-Forwarded-Protocol","https"},
            {"X-Url-Scheme","https"},
        };
        for (String[] dh : downgradeHeaders) {
            final String hn = dh[0], hv = dh[1];
            techs.add(new Technique("Protocol Downgrade", "Downgrade:" + dh[0] + "=" + dh[1],
                "Protocol downgrade via " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] combinedDown = {
            {"X-Forwarded-Proto","http","Host","localhost"},
            {"X-Forwarded-Proto","http","Host","127.0.0.1"},
            {"Front-End-Https","on","Host","localhost"},
            {"X-Url-Scheme","http","X-Forwarded-Host","localhost"},
        };
        for (String[] cd : combinedDown) {
            final String h1 = cd[0], v1 = cd[1], h2 = cd[2], v2 = cd[3];
            techs.add(new Technique("Protocol Downgrade", "DowngradeComb:" + cd[0],
                "Combined downgrade: " + h1 + "=" + v1 + " + " + h2 + "=" + v2,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, h1, v1); addHeader(c, h2, v2); return c; }));
        }

        String[][] conflictProto = {
            {"X-Forwarded-Proto","http","X-Url-Scheme","https"},
            {"X-Forwarded-Proto","https","Front-End-Https","on"},
            {"X-Forwarded-Proto","HTTP/1.0","X-Forwarded-Proto","http"},
        };
        for (String[] cp : conflictProto) {
            final String h1 = cp[0], v1 = cp[1], h2 = cp[2], v2 = cp[3];
            techs.add(new Technique("Protocol Downgrade", "DowngradeConflict:" + cp[0],
                "Conflicting protocol headers: " + h1 + "=" + v1 + " vs " + h2 + "=" + v2,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, h1, v1); addHeader(c, h2, v2); return c; }));
        }

        String[][] blankProto = {
            {"X-Forwarded-Proto",""},{"X-Forwarded-Proto"," "},
            {"X-Forwarded-Proto","null"},{"X-Forwarded-Proto","none"},
            {"X-Url-Scheme",""},{"X-Scheme",""},
        };
        for (String[] bp : blankProto) {
            final String hn = bp[0], hv = bp[1];
            techs.add(new Technique("Protocol Downgrade", "DowngradeBlank:" + bp[0] + "=" + bp[1].replace(" ", "SP"),
                "Blank protocol header: " + hn + ": '" + hv + "'",
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
