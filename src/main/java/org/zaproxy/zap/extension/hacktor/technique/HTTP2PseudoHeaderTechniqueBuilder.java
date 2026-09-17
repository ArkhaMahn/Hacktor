package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HTTP2PseudoHeaderTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "HTTP/2 Pseudo"; }
    @Override public int getOrder() { return 24; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] pseudoHeaders = {
            {":method","GET"},{":method","POST"},{":method","OPTIONS"},
            {":method","PUT"},{":method","DELETE"},
            {":path",ctx.baseClean},{":path","/"},{":path","/admin"},
            {":path","*"},{":authority","localhost"},{":authority","127.0.0.1"},
            {":authority","localhost:443"},{":scheme","https"},{":scheme","http"},
            {":protocol","websocket"},{":protocol","h2"},{":protocol","h2c"},
        };
        for (String[] ph : pseudoHeaders) {
            final String hn = ph[0], hv = ph[1];
            markRawAdd(techs, new Technique("HTTP/2 Pseudo", "H2Pseudo:" + ph[0].replace(":", "COL") + "=" + ph[1].replace("/", "SL"),
                "HTTP/2 pseudo-header: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] casePseudo = {
            {":Method","GET"},{":Path","/admin"},{":Authority","localhost"},
            {":method","GET"},{":SCHEME","https"},{":Protocol","websocket"},
        };
        for (String[] cp : casePseudo) {
            final String hn = cp[0], hv = cp[1];
            markRawAdd(techs, new Technique("HTTP/2 Pseudo", "H2PseudoCase:" + cp[0].replace(":", "COL") + "=" + cp[1],
                "Case-varied pseudo-header: " + hn + ": " + hv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }

        String[][] multiPseudo = {
            {":method","GET",":method","POST"},
            {":path","/",":path","/admin"},
            {":authority","localhost",":authority","evil.com"},
        };
        for (String[] mp : multiPseudo) {
            final String h1 = mp[0], v1 = mp[1], h2 = mp[2], v2 = mp[3];
            markRawAdd(techs, new Technique("HTTP/2 Pseudo", "H2Multi:" + mp[0].replace(":", "COL"),
                "Duplicate pseudo-header: " + h1 + ":" + v1 + " then " + h2 + ":" + v2,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, h1, v1); addHeader(c, h2, v2); return c; }));
        }
    }
}
