package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class RequestSmugglingTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Request Smuggling"; }
    @Override public int getOrder() { return 26; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] teValues = {
            "chunked","gzip","deflate","identity","compress",
            "gzip, chunked","gzip, deflate","deflate, gzip",
            "chunked, gzip","chunked, deflate","identity, chunked",
            "compress, gzip, deflate","gzip;q=1.0","deflate;q=1.0",
        };
        for (String te : teValues) {
            final String v = te;
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_E:" + te.replace(",", "C").replace(" ", "SP").replace(";", "SC"),
                "Transfer-Encoding: " + te,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Transfer-Encoding", v); return c; }));
        }

        String[] clValues = {
            "0","1","5","10","100","1000",
            "00","01"," 0","0 "," 0 ",
            "-1","9999999999","18446744073709551615",
        };
        for (String cl : clValues) {
            final String v = cl;
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_CL:" + cl.replace(" ", "SP"),
                "Content-Length: " + cl,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Content-Length", v); return c; }));
        }

        String[][] teclConflicts = {
            {"chunked","0"},{"chunked","1"},{"chunked","100"},
            {"chunked","-1"},{"gzip","0"},{"deflate","0"},
            {"identity","100"},{"chunked","999999"},
            {"gzip, chunked","0"},{"compress, gzip, deflate","0"},
        };
        for (String[] tc : teclConflicts) {
            final String te = tc[0], cl = tc[1];
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_TE_CL:" + te.replace(",", "C").replace(" ", "SP") + "_" + cl,
                "TE: " + te + " + CL: " + cl,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Transfer-Encoding", te); addHeader(c, "Content-Length", cl); return c; }));
        }

        String[][] emptyOrMissing = {
            {"Transfer-Encoding",""},{"Transfer-Encoding"," "},
            {"Transfer-Encoding","\t"},{"Transfer-Encoding","none"},
            {"Transfer-Encoding","identity"},{"Transfer-Encoding","chunked "},
            {"Transfer-Encoding"," chunked"},{"Transfer-Encoding","Chunked"},
        };
        for (String[] em : emptyOrMissing) {
            final String hn = em[0], hv = em[1];
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_TE_" + trunc(em[1].replace(" ", "SP").replace("-", "H"), 10),
                hv.isEmpty() ? "Remove Transfer-Encoding header" : "TE with value: '" + hv + "'",
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        for (String cl : new String[]{"1","10","100"}) {
            final String clVal = cl;
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_Identity_CL:" + cl,
                "TE: identity + CL: " + cl,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Transfer-Encoding", "identity"); addHeader(c, "Content-Length", clVal); return c; }));
        }

        markRawAdd(techs, new Technique("Request Smuggling", "SMT_CL0Body",
            "CL:0 with smuggled body (TE: chunked)",
            base -> {
                HttpMessage c = cloneMsg(base);
                addHeader(c, "Transfer-Encoding", "chunked");
                addHeader(c, "Content-Length", "0");
                try { c.getRequestBody().setBody("0\r\n\r\n"); } catch (Exception ignored) {}
                return c; }));

        String[][] teCaseVariants = {
            {"transfer-encoding","chunked"},{"Transfer-Encoding","Chunked"},
            {"TRANSFER-ENCODING","chunked"},{"transfer-encoding","CHUNKED"},
            {"Transfer-Encoding"," gzip, chunked "},{"Transfer-Encoding","chunked;"},
        };
        for (String[] tcv : teCaseVariants) {
            final String hn = tcv[0], hv = tcv[1];
            markRawAdd(techs, new Technique("Request Smuggling", "SMT_TECase:" + hn.replace("transfer-encoding", "TE").replace("-", ""),
                "TE header case variant: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
