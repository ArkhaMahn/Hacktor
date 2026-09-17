package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * API / resource version-path confusion.
 *
 * Many proxies and gateways rewrite or normalize versioned prefixes (v1, v2, api,
 * api-docs, swagger). Injecting an alternate or duplicated version prefix -- or a
 * traversal that collapses one -- can cause the proxy to route to a differently
 * protected handler than the one access control saw.
 */
public class VersionPathTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Version Path"; }
    @Override public int getOrder() { return 54; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] segments = ctx.rawSegments;
        if (segments.length == 0) return;

        // Prepend alternate version / api prefixes
        String[] prefixes = {
            "/v1", "/v2", "/v3", "/api", "/api/v1", "/api/v2", "/api/internal",
            "/v1/admin", "/2", "/v2/api", "/api/../", "/v1/../", "/api;",
        };
        for (String pfx : prefixes) {
            final String p = pfx;
            techs.add(new Technique("Version Path", "VerPre:" + trunc(pfx.replace("/","S").replace(".","D").replace(";","SC"), 12),
                "Prepend version prefix: " + pfx,
                base -> {
                    // Keep the original full path, prefixing (and normalizing a leading-slash-free form)
                    String tail = ctx.baseClean;
                    if (!tail.startsWith("/")) tail = "/" + tail;
                    String prefixed = p + tail;
                    HttpMessage c = cloneMsg(base); setPath.accept(c, prefixed); return c; }));
        }

        // Traversal between version segments to alias v1 -> v2
        for (int i = 1; i < segments.length; i++) {
            final int b = i;
            techs.add(new Technique("Version Path", "VerTrav:" + b,
                "Insert '/..' before segment [" + b + "] to alias version",
                base -> {
                    StringBuilder sb = new StringBuilder();
                    for (int s = 0; s < segments.length; s++) {
                        if (s == b) sb.append("/..");
                        sb.append("/").append(segments[s]);
                    }
                    HttpMessage c = cloneMsg(base); setPath.accept(c, sb.toString()); return c; }));
        }

        // Duplicate the whole resource under an api/version wrapper: /api/<orig>
        String[] wrappers = {
            "api", "v1", "v2", "internal", "api/v1", "api/v2", "admin", "user"
        };
        for (String w : wrappers) {
            final String wrap = w;
            techs.add(new Technique("Version Path", "VerWrap:" + wrap,
                "Wrap original path under '" + wrap + "' prefix: /" + wrap + ctx.baseClean,
                base -> {
                    String path = "/" + wrap + (ctx.baseClean.startsWith("/") ? ctx.baseClean : "/" + ctx.baseClean);
                    HttpMessage c = cloneMsg(base); setPath.accept(c, path); return c; }));
        }

        // Version suffix / duplicate version on same resource: /res/v1, /res/v2
        String[] suffixes = {
            "/v1", "/v2", "/admin", "/api", "/;", "/%2e", "/%2e%2e"
        };
        for (String s : suffixes) {
            final String suf = s;
            techs.add(new Technique("Version Path", "VerSuf:" + trunc(s.replace("/","S").replace(".","D").replace(";","SC"), 10),
                "Append version/suffix: " + s,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + suf); return c; }));
        }
    }
}
