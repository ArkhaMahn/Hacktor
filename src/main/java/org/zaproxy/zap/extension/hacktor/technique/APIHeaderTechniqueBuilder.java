package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class APIHeaderTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "API Headers"; }
    @Override public int getOrder() { return 32; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] apiHeaders = {
            {"X-Api-Version","1"},{"X-Api-Version","v1"},{"X-Api-Version","internal"},
            {"X-API-Version","latest"},{"X-Version","1.0"},{"X-API","1"},
            {"X-Namespace","admin"},{"X-Scope","admin"},{"Accept-Version","~1"},
            {"Accept-Version","v1"},{"X-Goog-Api-Version","v1"},{"Api-Version","2"},
            {"X-Api-Version","5"},{"Accept","application/vnd.api+json"},
            {"Accept","application/json;version=2"},{"Accept","application/json;d=1"},
            {"Accept","text/plain,application/json"}
        };
        for (String[] pair : apiHeaders) {
            final String hn = pair[0], hv = pair[1];
            techs.add(new Technique("API Headers", "ApiHdr:" + pair[1],
                "API negotiation header: " + pair[0] + ": " + pair[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
