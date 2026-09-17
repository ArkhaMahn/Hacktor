package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class WildcardTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Wildcard"; }
    @Override public int getOrder() { return 42; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] wildcards = {
            "/%2a","//*","/%2f%2a","/%2a/","//%2a",
            "/%2a%2a","/**","/%2a/","/*","/%2a.%2a",
            "/%2a.json","/%2a.xml","/%2a.php","/%2a.txt"
        };
        for (String ws : wildcards) {
            final String w = ws;
            techs.add(new Technique("Wildcard", "Wild:" + ws,
                "Wildcard append: " + ws,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + w); return c; }));
        }
    }
}
