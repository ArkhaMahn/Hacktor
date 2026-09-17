package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HeaderCaseTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Header Case"; }
    @Override public int getOrder() { return 30; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] caseFolded = {
            "x-forwarded-for","x-forwarded-FOR","X-FORWARDED-FOR",
            "x-Real-Ip","x-original-url","X-rewrite-url","x-custom-ip-authorization"
        };
        for (String hn : caseFolded) {
            final String h = hn;
            techs.add(new Technique("Header Case", "HdrCase:" + hn,
                "Case-folded header name: " + hn,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, h, "127.0.0.1"); return c; }));
        }
    }
}
