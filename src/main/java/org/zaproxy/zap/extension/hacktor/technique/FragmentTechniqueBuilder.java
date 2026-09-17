package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class FragmentTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Fragment"; }
    @Override public int getOrder() { return 17; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String lastSeg = ctx.lastSeg;
        String basePath = ctx.baseClean;
        String[] segments = ctx.rawSegments;
        String seg0 = segments.length > 0 ? segments[0] : "";

        // POSITION 0: Fragment BEFORE the first segment (LEADING / required)
        StringBuilder sbStart = new StringBuilder("/#");
        for (int sj = 0; sj < segments.length; sj++) {
            if (sj > 0) sbStart.append("/");
            sbStart.append(segments[sj]);
        }
        final String fragAtStart = sbStart.toString();
        markRawAdd(techs, new Technique("Fragment", "FragPos:0:START",
            "Fragment BEFORE first segment: " + fragAtStart,
            base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, fragAtStart); return c; }));

        // POSITIONS 1 to 2*(n-1): Fragment between each pair of segments
        for (int si = 0; si < segments.length - 1; si++) {
            String seg = segments[si];
            String nextSeg = segments[si + 1];

            StringBuilder sbA = new StringBuilder();
            for (int sj = 0; sj < segments.length; sj++) {
                if (sj == si) {
                    if (sj > 0) sbA.append("/");
                    sbA.append(segments[sj]).append("#/").append(segments[sj + 1]);
                    for (int sk = sj + 2; sk < segments.length; sk++)
                        sbA.append("/").append(segments[sk]);
                    break;
                }
                if (sj > 0) sbA.append("/");
                sbA.append(segments[sj]);
            }
            final String fragA = sbA.toString();
            markRawAdd(techs, new Technique("Fragment", "FragPos:" + (2 * si + 1) + ":A",
                "Fragment after segment [" + si + "] (" + seg + "#/" + nextSeg + "): " + fragA,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, fragA); return c; }));

            StringBuilder sbB = new StringBuilder();
            for (int sj = 0; sj < segments.length; sj++) {
                if (sj == si) {
                    if (sj > 0) sbB.append("/");
                    sbB.append(segments[sj]).append("/#").append(segments[sj + 1]);
                    for (int sk = sj + 2; sk < segments.length; sk++)
                        sbB.append("/").append(segments[sk]);
                    break;
                }
                if (sj > 0) sbB.append("/");
                sbB.append(segments[sj]);
            }
            final String fragB = sbB.toString();
            markRawAdd(techs, new Technique("Fragment", "FragPos:" + (2 * si + 2) + ":B",
                "Fragment after segment [" + si + "] (" + seg + "/#" + nextSeg + "): " + fragB,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, fragB); return c; }));
        }

        // FINAL POSITION: Fragment AFTER the last segment
        StringBuilder sbEnd = new StringBuilder();
        for (int sj = 0; sj < segments.length; sj++) {
            if (sj > 0) sbEnd.append("/");
            sbEnd.append(segments[sj]);
        }
        sbEnd.append("#/");
        final String fragAtEnd = sbEnd.toString();
        int lastPos = 2 * (segments.length - 1) + 1;
        markRawAdd(techs, new Technique("Fragment", "FragPos:" + lastPos + ":END",
            "Fragment AFTER last segment: " + fragAtEnd,
            base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, fragAtEnd); return c; }));

        // EMPTY PATH: Root URL fragments
        markRawAdd(techs, new Technique("Fragment", "FragEmpty:RootHash",
            "Empty path with fragment: /#",
            base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, "/#"); return c; }));
        markRawAdd(techs, new Technique("Fragment", "FragEmpty:RootHashOnly",
            "Empty path with hash-only fragment: #",
            base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, "#"); return c; }));
        String[] emptyFragments = {"/#admin","#admin","/#console","#console","/#dashboard","#dashboard",
            "/#api","#api","/#v1","#v1","/#source","#source"};
        for (String f : emptyFragments) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragEmpty:" + trunc(frag.replace("/", "S").replace("#", "H"), 12),
                "Empty path fragment: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // RARE: Encoded fragment delimiters
        String[] rareEncFragments = {"%23" + lastSeg, "%23/" + lastSeg, "#%23" + lastSeg,
            "%2523" + lastSeg, "%23%23" + lastSeg, "##" + lastSeg, "###" + lastSeg,
            "#" + lastSeg.replace("a", "%41"), "%23%23%23" + lastSeg};
        for (String f : rareEncFragments) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragRare:" + frag.replace("#", "H").replace("%", "P"),
                "Rare encoded fragment: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // CLASSIC: Single-encoded #
        String[] singleEncPos = {
            "/%23" + joinFromSegment(segments, 0),
            "/" + seg0 + "%23" + joinFromSegment(segments, 1),
        };
        for (int si = 0; si < segments.length - 1; si++) {
            singleEncPos = append(singleEncPos,
                new String[]{buildEncoded(segments, si, false, false, lastSeg)});
            singleEncPos = append(singleEncPos,
                new String[]{buildEncoded(segments, si, true, false, lastSeg)});
        }
        singleEncPos = append(singleEncPos, new String[]{
            basePath + "%23", basePath + "/%23",
        });
        for (String f : singleEncPos) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragEnc1:" + frag.replace("/", "S").replace("%", "P").replace("#", "H").substring(0, Math.min(20, frag.length())),
                "Single-encoded #: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // RARE: Double-encoded #
        String[] doubleEncPos = {
            "/%2523" + joinFromSegment(segments, 0),
            "/" + seg0 + "%2523" + joinFromSegment(segments, 1),
        };
        for (int si = 0; si < segments.length - 1; si++) {
            doubleEncPos = append(doubleEncPos,
                new String[]{buildEncoded(segments, si, false, true, lastSeg)});
            doubleEncPos = append(doubleEncPos,
                new String[]{buildEncoded(segments, si, true, true, lastSeg)});
        }
        doubleEncPos = append(doubleEncPos, new String[]{
            basePath + "%2523", basePath + "/%2523",
        });
        for (String f : doubleEncPos) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragEnc2:" + frag.replace("/", "S").replace("%", "P").replace("#", "H").substring(0, Math.min(20, frag.length())),
                "Double-encoded #: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // RARE: Triple-encoded #
        String[] tripleEncPos = {"/%252523" + joinFromSegment(segments, 0), basePath + "%252523"};
        for (String f : tripleEncPos) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragEnc3:" + frag.replace("/", "S").replace("%", "P").substring(0, Math.min(20, frag.length())),
                "Triple-encoded #: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // RARE: Mixed encoding
        String[] mixedEnc = {"#%23" + lastSeg, "%23#" + lastSeg,
            "#" + lastSeg + "%23", "%23" + lastSeg + "#",
            "##%23" + lastSeg, "%23##" + lastSeg};
        for (String f : mixedEnc) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragEncMix:" + frag.replace("#", "H").replace("%", "P"),
                "Mixed encoding: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // NOVEL: Encoded admin fragments
        String[] adminFragments = {"/admin","/administrator","/wp-admin","/console","/dashboard",
            "/manage","/internal","/api/v1","/api/v2","/v1","/v2","/source","/.git", "/.env"};
        for (String admin : adminFragments) {
            String[] enc = {"%23" + admin, "#" + admin,
                "%23" + admin.replace("/", "%2F"), "%23%2F" + admin.replace("/", ""),
                "#" + admin.replace("/", "%2F")};
            for (String e : enc) {
                final String frag = e;
                markRawAdd(techs, new Technique("Fragment", "FragAdminEnc:" + admin.replace("/", "S") + ":" +
                    trunc(e.replace("/", "S").replace("%", "P").replace("#", "H"), 16),
                    "Encoded fragment targeting " + admin + ": " + frag,
                    base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
            }
        }

        // NOVEL: Overlong UTF-8 encodings of #
        String[] overlongEnc = {"/%c0%a3" + lastSeg, "/%e0%80%a3" + lastSeg,
            "/%f0%80%80%a3" + lastSeg, "/%c0%a3" + basePath,
            "/%23" + lastSeg, "/" + lastSeg + "%c0%a3"};
        for (String f : overlongEnc) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragOverlong:" + trunc(frag.replace("/", "S").replace("%", "P"), 18),
                "Overlong/UTF-8 encoded #: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // NOVEL: Unicode confusables for #
        String[] confusableEnc = {"/\uFF03" + lastSeg, "/\uFE5F" + lastSeg,
            "/\u266F" + lastSeg, "/\u0374" + lastSeg, "/\u2023" + lastSeg};
        for (String f : confusableEnc) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragConfusable:" + Integer.toHexString(frag.charAt(1)) + ":" + lastSeg,
                "Unicode confusable for #: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // NOVEL: Case-varied encoding
        String[] caseEnc = {"/%c0%a3" + lastSeg, "/%C0%A3" + lastSeg,
            "/%E2%80%a3" + lastSeg, "/%c0%a3" + lastSeg};
        for (String f : caseEnc) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragCase:" + frag.substring(1, 5),
                "Case-varied encoding: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }

        // NOVEL: Query-embedded encoded fragments
        String[] queryEnc = {basePath + "?%23" + lastSeg, basePath + "?#" + lastSeg,
            basePath + "?%23" + lastSeg + "=1", basePath + "?frag=%23" + lastSeg};
        for (String f : queryEnc) {
            final String frag = f;
            markRawAdd(techs, new Technique("Fragment", "FragQuery:" +
                frag.substring(frag.length() - Math.min(10, frag.length())).replace("/", "S").replace("%", "P").replace("?", "Q").replace("#", "H"),
                "Encoded fragment in query: " + frag,
                base -> { HttpMessage c = cloneMsg(base); setPathWithFragment(c, frag); return c; }));
        }
    }
}
