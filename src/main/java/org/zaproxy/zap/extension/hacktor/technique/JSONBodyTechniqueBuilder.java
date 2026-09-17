package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class JSONBodyTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "JSON Body"; }
    @Override public int getOrder() { return 36; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] bodyMethods = {"POST","PUT","PATCH"};
        String[] jsonBodies = {
            "role=admin","isAdmin=true","admin=true","role:admin",
            "admin:1","user:admin","permission:admin","access:admin",
            "type:admin","group:admin","level:admin","scope:admin",
            "privilege=admin","is_admin=true","auth_level=admin"
        };

        for (String method : bodyMethods) {
            for (String jb : jsonBodies) {
                final String p = jb, m = method;
                String body = "{\"" + p.replaceFirst("[:=]", "\":\"") + "\"}";
                techs.add(new Technique("JSON Body", "JBody:" + method + ":" + jb,
                    "JSON body with field " + jb + " via " + method + " request",
                    base -> {
                        HttpMessage c = cloneMsg(base);
                        setMethod(c, m);
                        addHeader(c, "Content-Type", "application/json");
                        try { c.getRequestBody().setBody(body); } catch (Exception ignored) {}
                        return c; }));
            }
        }

        for (String jb : jsonBodies) {
            final String p = jb;
            String body = "{\"" + p.replaceFirst("[:=]", "\":\"") + "\"}";
            techs.add(new Technique("JSON Body", "JBodyOrig:" + jb,
                "Keep original method but set Content-Type: application/json with body " + jb,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "Content-Type", "application/json");
                    try { c.getRequestBody().setBody(body); } catch (Exception ignored) {}
                    return c; }));
        }

        String[] nestedBodies = {
            "{\"user\":{\"role\":\"admin\"}}",
            "{\"data\":{\"isAdmin\":true}}",
            "{\"auth\":{\"level\":\"admin\"}}",
            "{\"user\":{\"permissions\":[\"admin\"]}}",
            "{\"admin\":1,\"role\":\"admin\"}"
        };
        for (String nb : nestedBodies) {
            final String body = nb;
            techs.add(new Technique("JSON Body", "JBodyNested:POST",
                "Nested JSON body via POST: " + nb,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    setMethod(c, "POST");
                    addHeader(c, "Content-Type", "application/json");
                    try { c.getRequestBody().setBody(body); } catch (Exception ignored) {}
                    return c; }));
        }

        String[] formBodies = {
            "role=admin&isAdmin=true&admin=true",
            "user=admin&group=admin&access=admin"
        };
        for (String fb : formBodies) {
            final String body = fb;
            techs.add(new Technique("JSON Body", "JBodyForm:POST",
                "Form-urlencoded body via POST (content-type confusion): " + fb,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    setMethod(c, "POST");
                    addHeader(c, "Content-Type", "application/x-www-form-urlencoded");
                    try { c.getRequestBody().setBody(body); } catch (Exception ignored) {}
                    return c; }));
        }
    }
}
