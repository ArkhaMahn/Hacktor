package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Request-line / header aberrations that are "unexpected by the server": reserved-but-
 * ignored HTTP/2 connection preface, obs-fold header continuations (RFC 7230 §3.2.4
 * deprecated line folding), control characters (NUL, TAB) smuggled into header values
 * and request-targets, header names containing colons or empty names, CRLF inside the
 * request-target, network-path references ("//host", as in proxy-style absolute URIs),
 * and whitespace-prefixed methods. Most stacks either 400, silently tolerate, or —
 * in the interesting case — parse a different header/target than the value a stricter
 * parser saw, splitting behaviour between front end and origin.
 *
 * <p>All techniques here are raw-wire: the normal commons-httpclient sender would
 * re-normalise or strip them before the bytes ever reached the server.
 */
public class RawRequestAberrationsTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Raw Aberrations"; }
    @Override public int getOrder() { return 64; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String base = ctx.baseClean;
        if (base == null || base.isEmpty()) base = "/";
        final String basePath = base;

        // HTTP/2 cleartext preface ("PRI * HTTP/2.0\r\n...") — the server sees the
        // connection-preamble magic verb over an HTTP/1.x socket.
        markRawAdd(techs, new Technique("Raw Aberrations", "Preface:PRI",
            "HTTP/2 connection preface as the request line: PRI * HTTP/2.0",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setMethod(c, "PRI");
                setHTTPVersion(c, "HTTP/2.0");
                setLiteralPath(c, "*");
                return c; }));

        // RFC 7230 obs-fold: a header value with a CRLF + SP continuation. Front ends
        // that reject or unfold it pick up a different effective header value than
        // origins that concatenate, so Host spoofing can diverge between layers.
        markRawAdd(techs, new Technique("Raw Aberrations", "ObsFold:Host",
            "obs-fold Host continuation: evil.local folded onto real host",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Host", ctx.lastSeg.isEmpty()
                    ? "user.host\r\n evil.local" : ctx.lastSeg + "\r\n evil.local");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "ObsFold:XFH",
            "obs-fold X-Forwarded-Host continuation: 127.0.0.1 folded onto admin.internal",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("X-Forwarded-Host", "admin.internal\r\n 127.0.0.1");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "ObsFold:UA",
            "obs-fold User-Agent continuation injecting a marker line",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("User-Agent", "Mozilla/5.0\r\n X-Hacktor-Fold: 1");
                return c; }));

        // Control characters in header VALUES: NUL byte and tab after the colon.
        markRawAdd(techs, new Technique("Raw Aberrations", "Ctrl:NulHeader",
            "NUL byte inside a header value (X-Null: a\\u0000b)",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("X-Null", "a\u0000b");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "Ctrl:TabValue",
            "tab character inside a header value (X-Tab: a\\tb)",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("X-Tab", "a\tb");
                return c; }));

        // Malformed header NAMES: a colon inside the name, and an empty name.
        markRawAdd(techs, new Technique("Raw Aberrations", "Name:ColonInName",
            "header name containing a colon: 'X:Injected: 1' parses differently per stack",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("X:Injected", "1");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "Name:EmptyName",
            "empty header name: ': evil.local'",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("", "evil.local");
                return c; }));

        // Control characters in the REQUEST-TARGET: literal CRLF (splits into what a
        // lenient parser reads as a second header line) and a TAB segment.
        markRawAdd(techs, new Technique("Raw Aberrations", "Path:CrlfInTarget",
            "literal CRLF inside the request-target",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setLiteralPath(c, basePath + "/\r\nX-Hacktor-Split: 1");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "Path:TabInTarget",
            "literal tab inside the request-target",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setLiteralPath(c, basePath + "/\tsegment");
                return c; }));

        // Network-path reference (//host prefix, like an absolute-URI without scheme):
        // proxies that route on the authority see evil.local; strict origins see the path.
        markRawAdd(techs, new Technique("Raw Aberrations", "Path:NetPathRef",
            "network-path reference request-target: //evil.local" + basePath,
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setLiteralPath(c, "//evil.local" + basePath);
                return c; }));

        // Whitespace-prefixed method and trailing tab — verb-tampering at the byte level.
        markRawAdd(techs, new Technique("Raw Aberrations", "Method:LeadingSpace",
            "method with a leading space: ' GET /path HTTP/1.1'",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setMethod(c, " GET");
                return c; }));
        markRawAdd(techs, new Technique("Raw Aberrations", "Method:TrailingTab",
            "method verb with a trailing tab: 'GET\\t'",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                setMethod(c, "GET\t");
                return c; }));
    }
}