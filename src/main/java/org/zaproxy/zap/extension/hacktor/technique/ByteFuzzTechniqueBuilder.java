package org.zaproxy.zap.extension.hacktor.technique;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * Exhaustive single-character request-target sweep, ported from PortSwigger's
 * <em>URL Fuzzer 401/403 Bypass</em> Burp extension.
 *
 * <p>The upstream tool walks every byte value {@code 0x00..0xFE} (its
 * {@code charRange} default is 255) and, for each one, generates a family of
 * mutated request-targets at seven different positions in the path:
 *
 * <ol>
 *   <li><b>pre</b> — {@code <char>/admin/panel}: the character replaces nothing and
 *       sits in front of the leading slash, i.e. the request-target stops being
 *       origin-form at all;</li>
 *   <li><b>slash-pre</b> — {@code <char>//admin/panel};</li>
 *   <li><b>seg</b> — appended to the end of one path segment
 *       ({@code /admin<x>/panel}, {@code /admin/panel<x>/});</li>
 *   <li><b>trailing-dir</b> — {@code /admin/panel/<char>/};</li>
 *   <li><b>trailing-slash</b> — {@code /admin/panel<x>/};</li>
 *   <li><b>end</b> — {@code /admin/panel<x>}.</li>
 * </ol>
 *
 * <p>That is the "exploiting HTTP parsers inconsistencies" differential: a reverse
 * proxy, a CDN, a WAF and the origin server each tokenise the same
 * request-target differently, and a byte that one of them treats as a delimiter and
 * another treats as path data is the whole bypass. Upstream also supports fuzzing
 * with two (or more) characters at a time, which is a {@code 255^2} permutation
 * space; that is offered here as a bounded Novel-tier set over the characters that
 * actually matter, because the full cross-product is not runnable in one scan.
 *
 * <p><b>Response handling.</b> Upstream's {@code isBehaviorChanged()} throws away
 * two kinds of answer before it will call something a bypass, and so does this
 * family:
 * <ul>
 *   <li>{@code 400} / {@code 404} — upstream's comment is "behavior did change, it
 *       just errors out": the front end refused to parse the target at all. A {@code 404}
 *       in particular is a <em>weaker</em> answer than the {@code 401}/{@code 403} we
 *       started from, so reporting it as a bypass would be a false positive.</li>
 *   <li>an empty body — upstream notes "in case you \r\n, the web server waits
 *       forever"; a bare CR/LF in the request line makes the server wait for the rest
 *       of a request that will never come, so an empty answer is a dead connection
 *       rather than a served page.</li>
 * </ul>
 * Both rules are attached to each generated technique through
 * {@link Technique#setDiscardOn(int...)} / {@link Technique#setDiscardEmptyBody(boolean)}.
 *
 * <p>All probes are raw-wire: the prepended forms produce a non-origin-form
 * request-target, and control characters / high bytes would be re-encoded or rejected
 * by any URI-based sender.
 *
 * <p><b>Tiers.</b> Classic is the punctuation-and-whitespace set that HTTP parsers
 * genuinely disagree about. Rare is the full {@code 0x00..0xFE} sweep, which is mostly
 * control characters that answer {@code 400} and get dropped — useful, but noisy and
 * large. Novel is the multi-character and percent-encoded forms.
 */
public class ByteFuzzTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Byte Fuzz"; }
    @Override public int getOrder() { return 65; }

    @Override public Technique.Position getPosition() { return Technique.Position.URL; }


    private static final String FAMILY = "Byte Fuzz";

    /** The upstream fuzzing range: charArray[i] = (char) i for i in [0, charRange). */
    private static final int CHAR_RANGE = 255;

    /**
     * Statuses upstream refuses to treat as a bypass. See the class comment.
     * Shared by every probe in this family.
     */
    private static final int[] PARSE_ERROR_STATUSES = { 400, 404 };

    /**
     * Classic tier: the delimiters, whitespace and control bytes that different
     * HTTP parsers and reverse proxies disagree about.
     */
    private static final int[] CLASSIC_BYTES = {
        0x2E /* . */, 0x2F /* / */, 0x5C /* \ */, 0x3B /* ; */, 0x2A /* * */,
        0x3F /* ? */, 0x23 /* # */, 0x25 /* % */, 0x26 /* & */, 0x3D /* = */,
        0x2B /* + */, 0x2C /* , */, 0x3A /* : */, 0x40 /* @ */, 0x21 /* ! */,
        0x24 /* $ */, 0x27 /* ' */, 0x22 /* " */, 0x7C /* | */, 0x5E /* ^ */,
        0x3C /* < */, 0x3E /* > */, 0x60 /* ` */, 0x7B /* { */, 0x7D /* } */,
        0x5B /* [ */, 0x5D /* ] */, 0x7E /* ~ */,
        0x20 /* SP */, 0x09 /* TAB */, 0x0D /* CR */, 0x0A /* LF */, 0x00 /* NUL */
    };

    /**
     * Novel tier: the multi-character fuzzing upstream exposes through
     * {@code numberOfFuzzedCharsInURL}, bounded to the characters that have actually
     * produced parser-splitting bypasses. Two characters give 14x14 combinations per
     * position rather than the upstream 255x255.
     */
    private static final int[] DOUBLE_BYTES = {
        0x2E /* . */, 0x3B /* ; */, 0x2F /* / */, 0x5C /* \ */, 0x2A /* * */,
        0x3F /* ? */, 0x23 /* # */, 0x25 /* % */, 0x20 /* SP */, 0x09 /* TAB */,
        0x2C /* , */, 0x3A /* : */, 0x00 /* NUL */, 0x7E /* ~ */
    };

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        String path = ctx.baseClean;
        if (path == null || path.isEmpty()) path = "/";
        final String p = path;
        // Upstream fuzzes request.path(), which in Burp includes the query string, so
        // slashes inside a query value become insertion points there too. Hacktor
        // mutates the path and carries the query through untouched (as every other
        // family does), so the query is re-appended after the payload is placed.
        final String query = ctx.origQuery == null ? "" : ctx.origQuery;

        // Upstream tokenises on "/" and keeps the empty leading token, so the
        // segment loop below reproduces its exact output for paths like
        // "/admin/panel" and "//admin" (consecutive separators collapse there).
        String[] tokens = splitKeepingEmpty(p);

        for (int b = 0; b < CHAR_RANGE; b++) {
            final String payload = String.valueOf((char) b);
            VulnCatalog.Tier tier = isClassic(b) ? VulnCatalog.Tier.CLASSIC
                : VulnCatalog.Tier.RARE;
            emit(techs, p, query, tokens, payload, byteLabel(b), tier);
        }

        for (int i = 0; i < DOUBLE_BYTES.length; i++) {
            for (int j = 0; j < DOUBLE_BYTES.length; j++) {
                String payload = new String(new char[] {
                    (char) DOUBLE_BYTES[i], (char) DOUBLE_BYTES[j] });
                emit(techs, p, query, tokens, payload,
                    byteLabel(DOUBLE_BYTES[i]) + "+" + byteLabel(DOUBLE_BYTES[j]),
                    VulnCatalog.Tier.NOVEL);
            }
        }
    }

    // ─── Generation ───────────────────────────────────────────────────

    /**
     * Emits the six position variants upstream's {@code addPayloadToPaths()}
     * produces for one payload, de-duplicated. Upstream's seventh form
     * ({@code /<payload>/<path>}) only fires for paths that do not already start
     * with "/", which never happens for an HTTP request-target, so it is not
     * reproduced here.
     */
    private void emit(List<Technique> techs, String path, String query, String[] tokens,
                      String payload, String byteLabel, VulnCatalog.Tier tier) {
        Set<String> targets = new LinkedHashSet<>();

        // 1. payload immediately before the leading slash: ";admin" — the
        //    request-target is no longer origin-form.
        targets.add(payload + path);
        // 2. payload before the leading slash with a separator: ";/admin".
        targets.add(payload + "/" + path);
        // 3. appended to one segment: "/admin;/panel/".
        for (String segTarget : segmentTargets(tokens, payload)) targets.add(segTarget);
        // 4. as a new trailing directory segment: "/admin/panel/;/".
        if (!path.endsWith("/")) targets.add(path + "/" + payload + "/");
        // 5. glued to the end, keeping the trailing slash: "/admin/panel;/".
        targets.add(path + payload + "/");
        // 6. glued to the very end: "/admin/panel;".
        targets.add(path + payload);

        for (String variant : targets) {
            if (variant.isEmpty()) continue;
            final String t = variant + query;
            Technique tech = new Technique(FAMILY, "ByteFuzz:" + byteLabel + "@" + brief(variant),
                "URL Fuzzer character sweep: '" + describe(variant) + "'",
                base -> { HttpMessage c = cloneMsg(base); setTarget(c, t); return c; });
            tech.setTier(tier);
            tech.setDiscardOn(PARSE_ERROR_STATUSES);
            tech.setDiscardEmptyBody(true);
            markRawAdd(techs, tech);
        }
    }

    /**
     * Reproduces upstream's segment loop. The original builds each candidate with a
     * StringBuilder that only emits a "/" separator while the buffer does not already
     * start with one, and skips empty tokens entirely — so consecutive slashes in the
     * base path collapse and the candidate always ends with "/". The result for
     * "/admin/panel" is "/admin/panel/", "/admin;<x>/panel/" and "/admin/panel;<x>/";
     * the first of those carries no payload at all (upstream emits it anyway) and is
     * skipped here because it is a plain trailing-slash probe.
     */
    private static List<String> segmentTargets(String[] tokens, String payload) {
        List<String> out = new ArrayList<>();
        for (int j = 0; j < tokens.length; j++) {
            if (tokens[j].isEmpty()) continue; // nothing to append the payload to
            // Upstream emits a "/" before the first non-empty token and never again
            // (the buffer already starts with one), so every candidate is
            // "/" + token + payload + "/" + token + ... + "/".
            StringBuilder sb = new StringBuilder("/");
            for (int z = 0; z < tokens.length; z++) {
                if (tokens[z].isEmpty()) continue;
                sb.append(tokens[z]);
                if (z == j) sb.append(payload);
                sb.append("/");
            }
            out.add(sb.toString());
        }
        return out;
    }

    // ─── Labels ───────────────────────────────────────────────────────

    private static boolean isClassic(int b) {
        for (int c : CLASSIC_BYTES) if (c == b) return true;
        return false;
    }

    /** Human-readable name for a fuzzed byte, e.g. {@code 0x2E '.'} or {@code 0x01}. */
    static String byteLabel(int b) {
        String hex = String.format("0x%02X", b);
        if (b >= 0x20 && b < 0x7F) return hex + " '" + (char) b + "'";
        switch (b) {
            case 0x00: return hex + " NUL";
            case 0x09: return hex + " TAB";
            case 0x0A: return hex + " LF";
            case 0x0D: return hex + " CR";
            case 0x7F: return hex + " DEL";
            default:   return hex;
        }
    }

    /** Short printable form of a mutated target for the technique label. */
    private static String brief(String target) {
        String s = target;
        s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t").replace("\u0000", "\\0");
        return s.length() <= 34 ? s : s.substring(0, 34) + "..";
    }

    /** Printable form used in the description, printable chars left as-is. */
    private static String describe(String target) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            if (c == '\r') sb.append("\\r");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\t') sb.append("\\t");
            else if (c < 0x20 || c == 0x7F) sb.append(String.format("\\x%02X", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }

    /** Splits on "/" keeping empty tokens, matching {@code String.split("/")}. */
    private static String[] splitKeepingEmpty(String path) {
        List<String> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '/') { out.add(path.substring(start, i)); start = i + 1; }
        }
        out.add(path.substring(start));
        return out.toArray(new String[0]);
    }
}
