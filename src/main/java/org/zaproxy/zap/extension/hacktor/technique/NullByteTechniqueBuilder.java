package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class NullByteTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Null Byte"; }
    @Override public int getOrder() { return 38; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] nullChars = {
            "%00","%0d","%0a","%09","%00.",
            "%00%2e","%00..","..%00","..%00/",
            "%0d%0a","%0a%0d",
            "%c0%80","%e0%80%80","%00%00","%u0000",
            "%00/admin","admin%00","%00.json","admin%00.json"
        };
        for (String nc : nullChars) {
            final String p = nc;
            techs.add(new Technique("Null Byte", "Null:" + nc,
                "Append null/control character: " + nc,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + p); return c; }));
        }
    }
}
