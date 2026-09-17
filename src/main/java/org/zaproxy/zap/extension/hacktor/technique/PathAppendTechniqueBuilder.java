package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class PathAppendTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Path Append"; }
    @Override public int getOrder() { return 39; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] appendedSegs = {
            "*","%2a","**","x","dummy","foo","test","1","json",
            ".;","%3b","!","$",":","@","+","~",",",
            "%23","%3f","%2e","%2f","%252f","%25",
            "admin","debug","internal","secret","private","hidden",
            "backup","old","new","temp","tmp","dev","staging",
            ".git",".svn",".hg",".env",".htaccess","web.config",
            "config","settings","actuator","swagger","api-docs",
            "graphql","graphiql","_debug","__debug__","console",
            "shell","terminal","cmd","command","exec","eval"
        };
        for (String asp : appendedSegs) {
            final String p = asp;
            techs.add(new Technique("Path Append", "Append:" + asp,
                "Append segment '" + asp + "' to path",
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + "/" + p); return c; }));
        }
    }
}
