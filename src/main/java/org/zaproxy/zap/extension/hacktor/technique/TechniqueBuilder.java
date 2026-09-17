package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public interface TechniqueBuilder {
    void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath, PathContext ctx);
    String getFamily();
    int getOrder();

    class PathContext {
        public final String origPath;
        public final String basePath;
        public final String origQuery;
        public final String baseClean;
        public final String[] rawSegments;
        public final String lastSeg;
        public final String parent;

        public PathContext(String origPath, String basePath, String origQuery,
                          String baseClean, String[] rawSegments, String lastSeg, String parent) {
            this.origPath = origPath;
            this.basePath = basePath;
            this.origQuery = origQuery;
            this.baseClean = baseClean;
            this.rawSegments = rawSegments;
            this.lastSeg = lastSeg;
            this.parent = parent;
        }
    }
}
