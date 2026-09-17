package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.BiConsumer;

public class SegmentDupTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Segment Dup"; }
    @Override public int getOrder() { return 41; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        techs.add(new Technique("Segment Dup", "DupLast:" + ctx.lastSeg,
            "Duplicate the last path segment",
            base -> {
                HttpMessage c = cloneMsg(base);
                setPath.accept(c, ctx.parent + ctx.lastSeg + "/" + ctx.lastSeg);
                return c; }));
        for (int xr = 0; xr < ctx.rawSegments.length; xr++) {
            final int n = xr;
            techs.add(new Technique("Segment Dup", "SegDup:" + n,
                "Repeat segment [" + n + "] in-place",
                base -> {
                    List<String> seg = new ArrayList<>(Arrays.asList(ctx.rawSegments));
                    seg.add(n + 1, seg.get(n));
                    HttpMessage c = cloneMsg(base); setPath.accept(c, joinPath(seg.toArray(new String[0]))); return c; }));
        }
    }
}
