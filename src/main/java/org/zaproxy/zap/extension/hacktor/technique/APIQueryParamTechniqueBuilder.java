package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class APIQueryParamTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "API Headers"; }
    @Override public int getOrder() { return 33; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] apiQueryParams = {
            "format=json","format=xml","output=json","json=1",
            "type=json","callback=jsonp","debug=1","test=1","env=dev","env=internal",
            "component=admin","template=admin","view=admin","_method=GET",
            "XDEBUG_SESSION=1","ext=.json","o=.json","wiki=1","inline=1","preview=1"
        };
        for (String qp : apiQueryParams) {
            final String p = qp;
            techs.add(new Technique("API Headers", "ApiQ:" + qp,
                "API format-negotiation query param: " + qp,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    String q = ctx.origQuery.isEmpty() ? "?" : ctx.origQuery + "&";
                    replacePath(c, ctx.baseClean + q + p);
                    return c; }));
        }
    }
}
