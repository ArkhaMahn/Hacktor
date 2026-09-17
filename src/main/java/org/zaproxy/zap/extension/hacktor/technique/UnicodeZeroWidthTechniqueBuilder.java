package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class UnicodeZeroWidthTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Unicode Zero-Width"; }
    @Override public int getOrder() { return 47; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] zwPre = {
            "\u200B\u200B","\uFEFF","\u200B","\u2060","\u200D","\u00A0","\u200C",
            "\u200E","\u200F","\u2028","\u2029","\u202A","\u202B","\u202C",
            "\u202D","\u202E","\u2066","\u2067","\u2068","\u2069",
            "\u034F","\u061C","\u180E","\uFFF9","\uFFFA","\uFFFB",
            "\uFE00","\uFE01","\uFE02","\uFE03","\uFE04","\uFE05",
            "\uFE06","\uFE07","\uFE08","\uFE09","\uFE0A","\uFE0B",
            "\uFE0C","\uFE0D","\uFE0E","\uFE0F"
        };
        for (int zi = 0; zi < ctx.rawSegments.length; zi++) {
            final int n = zi;
            for (String zw : zwPre) {
                final String z = zw;
                techs.add(new Technique("Unicode Zero-Width", "UniZw:" + ctx.rawSegments[zi],
                    "Prepend zero-width character to segment [" + n + "]",
                    base -> {
                        String[] seg = ctx.rawSegments.clone();
                        seg[n] = z + seg[n];
                        HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg)); return c; }));
            }
        }
    }
}
