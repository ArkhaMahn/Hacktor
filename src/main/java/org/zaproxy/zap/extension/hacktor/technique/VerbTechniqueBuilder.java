package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

public class VerbTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Malformed Verbs"; }
    @Override public int getOrder() { return 20; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String[] caseVariants = {"get","Get","gET","GET","GeT","gEt","poSt","PoSt","PATCH","patch"};
        for (String bv : caseVariants) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbCase:" + bv,
                "Case-varied verb: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // The complete standard verb set, sent exactly, so verb-tampering access
        // control gaps (GET->POST->HEAD->TRACE/PATCH/OPTIONS/CONNECT/PUT/DELETE)
        // are covered on every target.
        String[] standardVerbs = {
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
        };
        for (String bv : standardVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbStd:" + bv,
                "Standard HTTP verb: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        String[] trailingSpace = {"GET ","GET  ","GET   ","POST ","PUT ","DELETE "};
        for (String bv : trailingSpace) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbSpace:" + v.trim() + "_" + v.length(),
                "Verb with trailing whitespace (" + v.length() + " spaces)",
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        String[] rareVerbs = {
            "XGET","GETX","GET?","GET#","GET.","GET,","GET;","GET0",
            "GET-1","GET.v2","POST0","DELETE0","PATCH0","GET@","GET+","GET=",
        };
        for (String bv : rareVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbRare:" + bv,
                "Rare verb variant: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        String[] realVerbs = {
            "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "REPORT", "VIEW", "CHECKOUT",
            "UNCHECKOUT", "SEARCH", "BULK", "ACL",
            "BASELINE-CONTROL", "VERSION-CONTROL",
            "LINK", "UNLINK", "PURGE", "BAN", "INVITE",
            "MKCALENDAR", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE",
            "M-SEARCH", "BREW", "WHEN",
        };
        for (String bv : realVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbReal:" + bv,
                "Less common but real HTTP verb: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // Additional RFC 3253 / RFC 4791 WebDAV-DeltaV and CalDAV verbs.
        String[] davVerbs = {
            "MKACTIVITY", "MERGE", "CHECKIN", "LABEL", "MKWORKSPACE",
            "MKREDIRECTREF", "UPDATEREDIRECTREF", "BIND", "UNBIND", "REBIND",
            "PATCH", "META", "POLL", "PRI", "MKRESOURCE",
        };
        for (String bv : davVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbDAV:" + bv,
                "WebDAV/DeltaV extended verb: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        markRawAdd(techs, new Technique("Malformed Verbs", "VerbH2:PRI",
            "HTTP/2 preface verb: PRI",
            base -> { HttpMessage c = cloneMsg(base); setMethod(c, "PRI"); return c; }));

        String[] customVerbs = {
            "FOO", "BAR", "BOGUS", "TEST", "DEBUG", "PROBE",
            "HEALTH", "PING", "STATUS", "INFO", "VERSION",
            "EXEC", "RUN", "EVAL", "CALL", "INVOKE",
            "INDEX", "REINDEX", "REBUILD", "RESET", "FLUSH",
            "REDIRECT", "SORT", "TLS", "TOKEN", "AUTH",
        };
        for (String bv : customVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbCustom:" + bv,
                "Custom/proprietary verb: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }

        // More custom verbs seen in real server stacks (CDN/purge, cache controls,
        // RPC transports, REST bridges) where implementing servers answer them.
        String[] moreCustomVerbs = {
            "UPDATE", "ADD", "MODIFY", "CREATE", "REMOVE",
            "LOOKUP", "LIST", "FETCH", "GETALL", "SET",
            "OPEN", "CLOSE", "PROCESS", "TRIGGER", "GENERATE",
            "IMPORT", "EXPORT", "SYNC", "CLEANUP", "AUDIT",
        };
        for (String bv : moreCustomVerbs) {
            final String v = bv;
            markRawAdd(techs, new Technique("Malformed Verbs", "VerbCustom2:" + bv,
                "Custom verb seen in the wild: " + bv,
                base -> { HttpMessage c = cloneMsg(base); setMethod(c, v); return c; }));
        }
    }
}
