package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class MatrixParamTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Matrix Params"; }
    @Override public int getOrder() { return 48; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] matrixParams = {
            ";jsessionid=x",";x=y",";admin=true",";&",";&jsessionid=x",";;",
            ";%00",";%0d",";%0a",";role=admin",";debug=true",";internal=true",
            ";phpsessid=x",";aspsessionid=x",";sid=x",
            ";callback=x",";jsonp=x",";cb=x",
            ";_method=GET",";method=GET",";__method=DELETE"
        };
        for (String mp : matrixParams) {
            final String p = mp;
            techs.add(new Technique("Matrix Params", "Matrix:" + mp,
                "Matrix/session parameter: " + mp,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + "/" + p); return c; }));
        }
    }
}
