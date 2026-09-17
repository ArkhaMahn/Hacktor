package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class MethodOverrideTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Method Override"; }
    @Override public int getOrder() { return 29; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] overrideHeaders = {
            "X-HTTP-Method-Override","X-HTTP-Method","X-Method-Override",
            "X-Original-HTTP-Method","X-Forwarded-Method","X-Method",
            "X-Original-Method","X-HTTP-Verb"
        };
        String[] overrideMethods = {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE","PROPFIND"};
        for (String oh : overrideHeaders) {
            for (String ov : overrideMethods) {
                final String hn = oh, hv = ov;
                techs.add(new Technique("Method Override", "MOverride:" + oh + "=" + ov,
                    "Set " + oh + ": " + ov,
                    base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
            }
        }
        techs.add(new Technique("Method Override", "MOverride:_method=GET",
            "Set Content-Type to form-urlencoded for _method override",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Content-Type", "application/x-www-form-urlencoded"); return c; }));

        String[] queryOverrides = {
            "_method=GET","_method=PUT","_method=DELETE",
            "__method=GET","__method=PUT","__method=DELETE",
            "X-HTTP-Method=GET","X-HTTP-Method=PUT","X-HTTP-Method=DELETE",
            "method=GET","method=PUT","method=DELETE"
        };
        for (String qo : queryOverrides) {
            final String p = qo;
            techs.add(new Technique("Method Override", "MOverrideQ:" + qo,
                "Query-based method override: " + qo,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + p);
                    return c; }));
        }
    }
}
