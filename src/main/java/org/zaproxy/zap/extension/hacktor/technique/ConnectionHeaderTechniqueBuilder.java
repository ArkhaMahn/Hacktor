package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class ConnectionHeaderTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Connection"; }
    @Override public int getOrder() { return 25; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] connHeaders = {
            {"Connection","close"},{"Connection","keep-alive"},
            {"Connection","Keep-Alive"},{"Connection","CLOSE"},
            {"Connection","upgrade"},{"Connection","Upgrade"},
            {"Connection","close, keep-alive"},{"Connection","keep-alive, close"},
            {"Connection","Transfer-Encoding"},{"Connection","TE"},
            {"Connection"," trailers"},{"Connection","trailer"},
            {"Connection",""},{"Connection"," "},
            {"Connection","\t"},{"Connection","\r\n"},
        };
        for (String[] ch : connHeaders) {
            final String hv = ch[1];
            techs.add(new Technique("Connection", "Conn:" + trunc(ch[1].replace(" ", "SP").replace("-", "H").replace("\t", "TAB").replace("\r", "CR").replace("\n", "LF").replace(",", "C"), 15),
                "Connection header: " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Connection", hv); return c; }));
        }

        String[][] kaHeaders = {
            {"Keep-Alive","timeout=0"},{"Keep-Alive","timeout=999999"},
            {"Keep-Alive","max=0"},{"Keep-Alive","max=999999"},
            {"Keep-Alive",""},{"Keep-Alive"," "},
            {"Keep-Alive","close"},{"Keep-Alive","timeout=0, max=0"},
            {"Keep-Alive","timeout=999999, max=999999"},
        };
        for (String[] ka : kaHeaders) {
            final String hv = ka[1];
            techs.add(new Technique("Connection", "KeepAlive:" + trunc(ka[1].replace("=", "EQ").replace(",", "C").replace(" ", "SP"), 15),
                "Keep-Alive header: " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Keep-Alive", hv); return c; }));
        }

        String[][] conflictConn = {
            {"Connection","close","Keep-Alive","keep-alive"},
            {"Connection","keep-alive","Keep-Alive","close"},
            {"Connection","upgrade","Keep-Alive","timeout=999"},
        };
        for (String[] cc : conflictConn) {
            final String v1 = cc[1], v2 = cc[3];
            techs.add(new Technique("Connection", "ConnConflict:" + v1.replace("-", "H"),
                "Conflicting Connection:close + Keep-Alive:keep-alive",
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Connection", v1); addHeader(c, "Keep-Alive", v2); return c; }));
        }

        String[][] proxyConn = {
            {"Proxy-Connection","close"},{"Proxy-Connection","keep-alive"},
            {"Proxy-Connection","close, keep-alive"},{"Proxy-Connection",""},
            {"Proxy-Connection","0"},{"Proxy-Connection","1"},
        };
        for (String[] pc : proxyConn) {
            final String hv = pc[1];
            techs.add(new Technique("Connection", "ProxyConn:" + trunc(pc[1].replace(" ", "SP").replace("-", "H").replace(",", "C"), 15),
                "Proxy-Connection header: " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Proxy-Connection", hv); return c; }));
        }
    }
}
