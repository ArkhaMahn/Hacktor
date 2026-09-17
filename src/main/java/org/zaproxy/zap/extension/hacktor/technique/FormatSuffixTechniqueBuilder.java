package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class FormatSuffixTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Format Suffix"; }
    @Override public int getOrder() { return 40; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] formatSuffixes = {
            ".json",".xml",".php",".do",".action",".jsp",".html",".css",".js",
            ".map",".bak",".old",".txt",".xls",".zip",".tar.gz","!default",
            "!do",";.css","/.","/..;",".json;","%3b.css","/../",
            ".aspx",".asp",".cgi",".fcgi",".pl",".py",".rb",".go",
            ".yaml",".yml",".toml",".ini",".conf",".config",
            ".env",".config.json",".config.xml",".config.yaml",
            "._json",".jsonl",".ndjson",".hal",".hal+json",
            ".jsonld",".atom",".rss",".svg",".pdf",
            ".exe",".dll",".so",".dylib",".war",".ear"
        };
        for (String suf : formatSuffixes) {
            final String s = suf;
            techs.add(new Technique("Format Suffix", "SuffixApp:" + suf,
                "Append format suffix: " + suf,
                base -> { HttpMessage c = cloneMsg(base); setPath.accept(c, ctx.baseClean + s); return c; }));
        }
    }
}
