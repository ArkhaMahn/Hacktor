package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HTTPVersionTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "HTTP Version"; }
    @Override public int getOrder() { return 21; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] classicVersions = {"HTTP/0.9","HTTP/1.0","HTTP/1.1","HTTP/2.0","HTTP/3.0"};
        for (String v : classicVersions) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerClassic:" + v.replace("/", "_"),
                "Use HTTP version: " + v,
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] rareVersions = {"HTTP/1","HTTP/2","HTTP/3","HTTP/1.10","HTTP/1.01",
            "HTTP/1.2","HTTP/1.9","HTTP/2.1","HTTP/2.2","HTTP/3.1",
            "HTTP/4.0","HTTP/9.9","HTTP/10.0","HTTP/1.255","HTTP/1.65535"};
        for (String v : rareVersions) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerRare:" + v.replace("/", "_"),
                "Rare/non-standard HTTP version: " + v,
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] caseVersions = {"http/1.1","Http/1.1","HTTP/1.0","http/1.0",
            "HTTP/0.9","http/0.9","HTTP/2","http/2","HTTP/3","http/3"};
        for (String v : caseVersions) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerCase:" + v.replace("/", "_"),
                "Case variation of HTTP version: " + v,
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] wsVersions = {"HTTP/1.1 ","HTTP/1.1  ","HTTP/1.1\t","HTTP/1.1\t\t",
            " HTTP/1.1","HTTP/ 1.1","HTTP /1.1","HTTP\t/1.1"};
        for (String v : wsVersions) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerWS:" + v.replace("/", "_").replace(" ", "SP").replace("\t", "TB"),
                "Version with whitespace: '" + v + "'",
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] novelGarbage = {"HTTP/1.1xyz","HTTP/1.1/","HTTP/1.1\n","HTTP/1.1\r\n",
            "HTTP/1.1.","HTTP/1.1-","HTTP/1.1x","HTTP/1.1.1","HTTP/1.1.1.1","HTTP/1.1.2.3.4",
            "HTTP/1.1extra","HTTP/1. ","HTTP/1.1\t","HTTP/1.1/","HTTP/1.1@","HTTP/1.1#","HTTP/1.1?","HTTP/1.1="};
        for (String v : novelGarbage) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerNovel:" + v.replace("/", "_").replace(" ", "SP").replace("\t", "TB").replace(".", "DOT").replace("?", "Q").replace("=", "EQ").replace("#", "H").replace("@", "AT"),
                "Version with garbage: '" + v + "'",
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] novelProtocol = {"HTTP1/1.1","HTTP:/1.1","HTTP//1.1","HTTP:///1.1",
            "HTTPS/1.1","HTTPS:/1.1","HTTP2/1.1","HTTP2/2.0","HTTP3/3.0",
            "SPDY/3.1","SPDY/3","h2","h2c","HTTP/2","HTTP/2.0","HTTP/3","HTTP/3.0",
            "HTTP/QUIC","HTTP/UDP","HTTP/1.1UDP"};
        for (String v : novelProtocol) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerProto:" + v.replace("/", "_").replace(".", "D"),
                "Protocol confusion: '" + v + "'",
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }

        String[] novelCRLF = {"HTTP/1.1\r\nX-Injected: true","HTTP/1.1\r\nHost: evil.com",
            "HTTP/1.1\r\nSet-Cookie: evil","HTTP/1.1%0d%0aX-Injected: true",
            "HTTP/1.1%0aX-Injected: true","HTTP/1.1\rX-Injected: true"};
        for (String v : novelCRLF) {
            final String ver = v;
            markRawAdd(techs, new Technique("HTTP Version", "VerCRLF:" + v.replace("/", "_").replace("%", "P").replace(" ", "SP").replace("\r", "CR").replace("\n", "LF"),
                "Version with CRLF injection: '" + ver + "'",
                base -> { HttpMessage c = cloneMsg(base); setHTTPVersion(c, ver); return c; }));
        }
    }
}
