package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class PaddingTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Padding"; }
    @Override public int getOrder() { return 19; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] pads = {"%20","%09","%20%20","%09%09","%a0",
            "%20%09","%09%20","%0d%0a","%0a%0d",
            "%c2%a0","%e2%80%83","%e2%80%8b","%e2%80%8c","%e2%80%8d",
            "%ef%bb%bf","%ef%bf%bd","%c3%82","%c2%80",
            "%20%0d","%20%0a","%0d%20","%0a%20"};
        for (String pad : pads) {
            final String p = pad;
            String full = ctx.baseClean + p;
            techs.add(new Technique("Padding", "Pad:" + ctx.lastSeg + pad,
                "Append whitespace padding '" + pad + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, full); return c; }));
        }
    }
}
