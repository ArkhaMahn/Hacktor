package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public interface TechniqueBuilder {
    void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath, PathContext ctx);
    String getFamily();
    int getOrder();

    /**
     * The request surface every technique this builder emits targets.
     *
     * <p>Returning null (the {@link AbstractTechniqueBuilder} default) means the
     * builder does not claim a single surface, either because it is mixed — a
     * builder that writes both headers and query parameters must stamp each
     * technique individually — or because it is a request-level family. The engine
     * only fills in a missing position, so a per-technique value set inside
     * {@link #build} always wins.
     */
    Technique.Position getPosition();

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
