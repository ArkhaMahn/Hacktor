package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class RequestLineTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Request Line"; }
    @Override public int getOrder() { return 22; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        markRawAdd(techs, new Technique("Request Line", "ReqLine:Asterisk",
            "Asterisk-form request target: OPTIONS * HTTP/1.1",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "OPTIONS"); setHTTPVersion(c, "HTTP/1.1");
                replacePath(c, "*"); return c; }));

        markRawAdd(techs, new Technique("Request Line", "ReqLine:Authority",
            "Authority-form: CONNECT localhost:443",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "CONNECT"); setHTTPVersion(c, "HTTP/1.1");
                replacePath(c, "localhost:443"); return c; }));

        String[] absForms = {
            "http://127.0.0.1" + ctx.baseClean, "https://127.0.0.1" + ctx.baseClean,
            "http://localhost" + ctx.baseClean, "https://localhost" + ctx.baseClean,
            "http://[::1]" + ctx.baseClean, "http://0.0.0.0" + ctx.baseClean,
            "http://127.1" + ctx.baseClean,
        };
        for (String af : absForms) {
            final String form = af;
            markRawAdd(techs, new Technique("Request Line", "ReqLine:Abs:" + af.replace("http://", "").replace("/", "_"),
                "Absolute-form with different host: " + af,
                base -> { HttpMessage c = cloneMsg(base); replacePath(c, form); return c; }));
        }

        String[] optionsForms = {
            ctx.baseClean, ctx.baseClean + "/", "http://localhost" + ctx.baseClean,
        };
        for (String of : optionsForms) {
            final String form = of;
            markRawAdd(techs, new Technique("Request Line", "ReqLine:Options:" + trunc(of.replace("http://", "H").replace("/", "S").replace(":", "C").replace(".", "D"), 20),
                "OPTIONS method with path: " + of,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, "OPTIONS"); replacePath(c, form); return c; }));
        }

        markRawAdd(techs, new Technique("Request Line", "ReqLine:GETAsterisk",
            "GET * HTTP/1.1 (GET with asterisk-form)",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "GET"); setHTTPVersion(c, "HTTP/1.1");
                replacePath(c, "*"); return c; }));

        markRawAdd(techs, new Technique("Request Line", "ReqLine:POSTAsterisk",
            "POST * HTTP/1.1 (POST with asterisk-form)",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "POST"); setHTTPVersion(c, "HTTP/1.1");
                replacePath(c, "*"); return c; }));

        markRawAdd(techs, new Technique("Request Line", "ReqLine:NoVersion",
            "Request line without HTTP version",
            base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ""); return c; }));

        markRawAdd(techs, new Technique("Request Line", "ReqLine:PathOnly",
            "Send only path (no leading /) as request-target",
            base -> { HttpMessage c = cloneMsg(base); String pathOnly = ctx.baseClean.replaceFirst("^/", ""); replacePath(c, pathOnly); return c; }));

        markRawAdd(techs, new Technique("Request Line", "ReqLine:DoubleSpace",
            "Double-space in request line: GET  /path",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "GET "); return c; }));
    }
}
