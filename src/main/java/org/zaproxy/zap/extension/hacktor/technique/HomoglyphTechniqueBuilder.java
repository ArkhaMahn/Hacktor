package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class HomoglyphTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Homoglyph"; }
    @Override public int getOrder() { return 18; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        for (int hi = 0; hi < ctx.rawSegments.length; hi++) {
            final int ix = hi;
            final String sg = ctx.rawSegments[hi];
            final String fw = toFullwidth(sg);
            if (!fw.equals(sg)) {
                techs.add(new Technique("Homoglyph", "Homo:" + sg,
                    "Fullwidth/Unicode homoglyph for segment [" + ix + "]",
                    base -> {
                        String[] seg = ctx.rawSegments.clone(); seg[ix] = fw;
                        HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg)); return c; }));
            }
        }
    }
}
