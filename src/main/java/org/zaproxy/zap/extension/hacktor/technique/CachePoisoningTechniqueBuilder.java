package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class CachePoisoningTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Cache Poisoning"; }
    @Override public int getOrder() { return 27; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] cacheHeaders = {
            {"Cache-Control","no-cache"},{"Cache-Control","no-store"},
            {"Cache-Control","max-age=0"},{"Cache-Control","private"},
            {"Cache-Control","public"},{"Cache-Control","must-revalidate"},
            {"Cache-Control","proxy-revalidate"},{"Cache-Control","no-transform"},
            {"Cache-Control","immutable"},{"Cache-Control","stale-while-revalidate=999999"},
            {"Cache-Control","max-stale=999999"},{"Cache-Control","min-fresh=999999"},
            {"Pragma","no-cache"},{"Pragma","no-store"},
            {"Expires","0"},{"Expires","-1"},
            {"Expires","Thu, 01 Jan 2000 00:00:00 GMT"},
            {"Expires","Fri, 18 Dec 2099 23:59:59 GMT"},
            {"Vary","*"},{"Vary","Accept-Encoding"},
            {"Vary","Cookie"},{"Vary","User-Agent"},
            {"Vary","Host"},{"Vary","X-Forwarded-For"},
            {"Vary","Accept,Accept-Encoding,Cookie,X-Forwarded-For"},
            {"Age","0"},{"Age","999999"},{"Age","-1"},
            {"If-None-Match","*"},
            {"If-Modified-Since","Sat, 01 Jan 2000 00:00:00 GMT"},
            {"If-Unmodified-Since","Sat, 01 Jan 2000 00:00:00 GMT"},
        };
        for (String[] ch : cacheHeaders) {
            final String hn = ch[0], hv = ch[1];
            techs.add(new Technique("Cache Poisoning", "Cache:" + ch[0] + "=" + trunc(ch[1].replace(" ", "SP").replace(",", "C").replace("=", "EQ"), 20),
                "Cache header: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] dupCache = {
            {"Cache-Control","no-cache","Cache-Control","max-age=0"},
            {"Cache-Control","private","Cache-Control","public"},
            {"Cache-Control","no-store","Cache-Control","public"},
            {"Vary","Cookie","Vary","User-Agent"},
            {"Vary","*","Vary","Accept-Encoding"},
        };
        for (String[] dc : dupCache) {
            final String h1 = dc[0], v1 = dc[1], h2 = dc[2], v2 = dc[3];
            techs.add(new Technique("Cache Poisoning", "CacheDup:" + dc[0],
                "Duplicate cache header: " + h1 + ":" + v1 + " + " + h2 + ":" + v2,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, h1, v1); addHeader(c, h2, v2); return c; }));
        }

        techs.add(new Technique("Cache Poisoning", "CacheVaryStar",
            "Vary: * (vary by everything)",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Vary", "*"); return c; }));

        techs.add(new Technique("Cache Poisoning", "CacheVaryAdmin",
            "Vary with admin reference: Vary: X-Admin-Token",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Vary", "X-Admin-Token"); return c; }));
    }
}
