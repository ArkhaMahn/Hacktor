package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;

/**
 * Lowercase HTTP method probes.
 *
 * <p>Some servers, proxies, and WAFs normalise the method to uppercase before
 * applying access-control rules but leave lower/method parsing to the
 * application framework, which accepts it verbatim. The mismatch yields a
 * 403/200 differential.
 *
 * <p>Sub-techniques:
 * <ul>
 *   <li><b>Classic</b> — fully lowercase standard methods ({@code get},
 *       {@code post}, {@code put}, {@code head}, {@code options}).</li>
 *   <li><b>Rare</b> — trailing whitespace on lowercased methods, mixed-case
 *       variants where only one half is lowered, and lowercased WebDAV/rarer
 *       methods (some IIS/Mongo stacks route on case-sensitive token
 *       comparisons).</li>
 *   <li><b>Novel</b> — methods lowercased but with raw whitespace / NUL
 *       padding that survives percent-free parsers; methods lowercased with
 *       HTTP-version pseudo-versioning attached (e.g. {@code get http/1.1});
 *       case-folded Unicode (fullwidth / small-caps) forms.</li>
 * </ul>
 */
public class LowercaseMethodTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Lowercase Method"; }

    @Override public int getOrder() { return 60; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {

        // ── Classic — fully lowercase standard methods ───────────────────
        String[] classic = {"get", "post", "put", "head", "options", "delete", "patch"};
        for (String m : classic) {
            addLowerMethod(techs, m, "classic");
        }

        // ── Rare — trailing whitespace on lowercased methods ────────────
        String[] trailingSpace = {
            "get ", "get  ", "get\t", "post ", "put\t", "head ", "delete ", "options "
        };
        for (String m : trailingSpace) {
            final String v = m;
            markRawAdd(techs, new Technique(getFamily(),
                "MethodLowerTrailing:" + v.replace(" ", "_S").replace("\t", "_T"),
                "Lowercase method with trailing whitespace: '" + v.replace("\t", "\\t") + "'",
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // ── Rare — mixed-case single halves ─────────────────────────────
        // Some servers normalise ALL-UPPER or all-lower, but skip mixed case.
        String[] mixedCase = {"Get", "gET", "PoSt", "pOsT", "OpTiOnS", "HeAd"};
        for (String m : mixedCase) {
            addLowerMethod(techs, m, "mixed");
        }

        // ── Rare — lowercased WebDAV / real verbs ───────────────────────
        String[] rareVerbs = {
            "propfind", "proppatch", "mkcol", "copy", "move",
            "lock", "unlock", "report", "view", "checkout",
            "uncheckout", "search", "bulk", "acl", "purge",
            "ban", "invite", "mkcalendar", "notify", "subscribe",
            "unsubscribe", "link", "unlink"
        };
        for (String m : rareVerbs) {
            addLowerMethod(techs, m, "rare-verb");
        }

        // ── Novel — case-folded Unicode forms ───────────────────────────
        // Fullwidth lowercase letters (U+FF41..U+FF5A) — some parsers
        // NFKC-fold and treat as ASCII, others route by raw byte comparison.
        String[] fullwidthLower = {"ｇｅｔ", "ｐｏｓｔ", "ｐｕｔ", "ｄｅｌｅｔｅ", "ｈｅａｄ"};
        for (String m : fullwidthLower) {
            final String v = m;
            markRawAdd(techs, new Technique(getFamily(),
                "MethodLowerFullwidth:" + v,
                "Fullwidth Unicode method: " + v,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // ── Novel — lowercase + NUL / control-char padding ──────────────
        String[] nullPadded = {"get\u0000", "post\u0000", "head\u0000", "options\u0000"};
        for (String m : nullPadded) {
            final String v = m;
            markRawAdd(techs, new Technique(getFamily(),
                "MethodLowerNul:" + v.replace("\u0000", "\\NUL"),
                "Lowercase method with NUL terminator",
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // ── Novel — lowercase + percent-encoded space (raw wire) ────────
        String[] pctSpaced = {"get%20", "post%20", "head%20", "options%20"};
        for (String m : pctSpaced) {
            final String v = m;
            markRawAdd(techs, new Technique(getFamily(),
                "MethodLowerPctSpace:" + v,
                "Lowercase method with percent-encoded space suffix",
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }
    }

    private void addLowerMethod(List<Technique> techs, String method, String kind) {
        final String v = method;
        markRawAdd(techs, new Technique(getFamily(),
            "MethodLower[" + kind + "]:" + method,
            "Lowercase / " + kind + " HTTP method: " + method,
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
    }
}