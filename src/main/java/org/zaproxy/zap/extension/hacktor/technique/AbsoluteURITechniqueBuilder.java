package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class AbsoluteURITechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Absolute URI"; }
    @Override public int getOrder() { return 37; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] absURIs = {
            "http://localhost" + ctx.baseClean,
            "https://localhost" + ctx.baseClean,
            "http://127.0.0.1" + ctx.baseClean,
            "https://127.0.0.1" + ctx.baseClean,
            "http://[::1]" + ctx.baseClean,
            "https://[::1]" + ctx.baseClean,
            "http://0x7f000001" + ctx.baseClean,
            "http://0177.0.0.1" + ctx.baseClean,
            "http://2130706433" + ctx.baseClean,
            "HTTP://localhost" + ctx.baseClean,
            "Http://localhost" + ctx.baseClean,
            "http:/" + ctx.baseClean,
            "//" + ctx.baseClean,
            "//localhost" + ctx.baseClean,
            "http://0.0.0.0" + ctx.baseClean,
            "http://192.168.1.1" + ctx.baseClean,
            "http://10.0.0.1" + ctx.baseClean,
        };
        for (String abs : absURIs) {
            final String a = abs;
            techs.add(new Technique("Absolute URI", "Abs:" + abs,
                "Absolute-form request target: " + abs,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, a); return c; }));
        }
    }
}
