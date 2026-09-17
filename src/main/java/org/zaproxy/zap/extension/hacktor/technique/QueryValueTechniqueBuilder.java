package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class QueryValueTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Query Values"; }
    @Override public int getOrder() { return 34; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] valueParams = {
            "role[]=admin","role=admin","role[0]=admin","role[]=1",
            "isAdmin=true","isAdmin=1","admin","admin=true","admin=1",
            "group=admin","group[]=admin","type=admin","access=admin",
            "access[]=admin","permission=admin","permissions[]=admin",
            "privilege=admin","scope=admin","role=1","role=true",
            "admin=on","is_admin=1","is_admin=true","user=admin"
        };
        for (String vp : valueParams) {
            final String p = vp;
            techs.add(new Technique("Query Values", "Val:" + vp,
                "Query value form: " + vp,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + p);
                    return c; }));
        }
    }
}
