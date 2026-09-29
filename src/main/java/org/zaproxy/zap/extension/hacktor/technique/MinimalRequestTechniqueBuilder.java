package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * Request-line / header-set mutations ported from PortSwigger's <em>403 Bypasser</em>
 * Burp extension, which ships two non-payload bypasses alongside its header and path
 * payload lists.
 *
 * <ul>
 *   <li><b>POST + empty Content-Length</b> — {@code tryBypassWithPOSTAndEmptyCL()}.
 *       The verb is changed from GET to POST and a <em>second</em>
 *       {@code Content-Length: 0} header line is appended without touching the
 *       original one or the body. A front end that reads the first
 *       {@code Content-Length} and an origin that reads the last (or that follows
 *       {@code Transfer-Encoding}) then disagree about where the request ends, and
 *       method-based authorisation on the front end is bypassed by the verb change
 *       on its own. The reference tool only issues this against GET requests, and so
 *       does this builder — on any other base verb the technique reports itself as
 *       not applicable instead of firing a redundant probe.</li>
 *   <li><b>HTTP/1.0, no headers</b> — {@code tryBypassWithDowngradedHttpAndNoHeaders()}.
 *       The request is rebuilt from the request line alone: no {@code Host}, no
 *       {@code User-Agent}, no {@code Accept}, nothing. There is no authority left for
 *       a virtual host or an ACL rule to match, and HTTP/1.0 clients are not entitled
 *       to the keep-alive / chunked behaviour a stricter rule may assume.</li>
 * </ul>
 *
 * <p>Both are raw-wire: with every header removed there is no {@code Host} for ZAP's
 * normal sender to route on, and the duplicate {@code Content-Length} would be
 * normalised away.
 */
public class MinimalRequestTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Minimal Request"; }
    @Override public int getOrder() { return 67; }

    @Override public Technique.Position getPosition() { return Technique.Position.REQUEST; }


    private static final String FAMILY = "Minimal Request";

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {

        // GET -> POST with an extra "Content-Length: 0" line, original body kept.
        // 403 Bypasser only sends this probe against GET requests (an already-POST
        // body cannot be re-framed by a method change), so a non-GET base yields a
        // null mutation, which the engine treats as "not applicable" and skips.
        Technique post = new Technique(FAMILY, "Post:DuplicateCL0",
            "GET->POST with a second, conflicting 'Content-Length: 0' header "
                + "(403 Bypasser: POST + empty CL); the original CL and body are kept. "
                + "Skipped when the base request is not a GET",
            base -> {
                if (!"GET".equalsIgnoreCase(methodOf(base))) return null;
                HttpMessage c = cloneMsg(base);
                setMethod(c, "POST");
                try { c.getRequestHeader().addHeader("Content-Length", "0"); }
                catch (Exception ignored) {}
                return c; });
        post.setTier(VulnCatalog.Tier.RARE);
        markRawAdd(techs, post);

        // Request line only: no headers at all, HTTP/1.0.
        Technique bare = new Technique(FAMILY, "Bare:HTTP/1.0-NoHeaders",
            "request line only - every header removed, downgraded to HTTP/1.0, "
                + "body unchanged (403 Bypasser: downgraded HTTP and no headers)",
            base -> { HttpMessage c = cloneMsg(base);
                setHTTPVersion(c, "HTTP/1.0");
                stripAllHeaders(c);
                return c; });
        bare.setTier(VulnCatalog.Tier.RARE);
        markRawAdd(techs, bare);

        // Same header strip on its own, so the "no Host to authorise against"
        // variable is isolated from the protocol-version change.
        Technique noHeaders = new Technique(FAMILY, "Bare:NoHeaders",
            "every request header removed (no Host, no User-Agent), body unchanged",
            base -> { HttpMessage c = cloneMsg(base);
                stripAllHeaders(c);
                return c; });
        noHeaders.setTier(VulnCatalog.Tier.RARE);
        markRawAdd(techs, noHeaders);

        // The 403 Bypasser also rebuilds the request for every header payload with
        // buildHttpMessage(), which drops the body offset handling entirely. A body
        // left attached to a request whose Content-Length says zero is the same
        // "two parsers, two request lengths" primitive from the other direction, so
        // it is worth having: POST, keep the original Content-Length, body intact.
        // Like the probe above it only makes sense on a GET base.
        Technique keepBody = new Technique(FAMILY, "Post:BodyWithoutCL",
            "POST whose body contradicts its own Content-Length: 0 (the 403 "
                + "Bypasser's buildHttpMessage() keeps the body while the header says zero). "
                + "Skipped when the base request is not a GET",
            base -> {
                if (!"GET".equalsIgnoreCase(methodOf(base))) return null;
                HttpMessage c = cloneMsg(base);
                setMethod(c, "POST");
                try { c.getRequestHeader().setHeader("Content-Length", "0"); }
                catch (Exception ignored) {}
                return c; });
        keepBody.setTier(VulnCatalog.Tier.NOVEL);
        markRawAdd(techs, keepBody);
    }

    private static String methodOf(HttpMessage m) {
        try { return m.getRequestHeader().getMethod(); } catch (Exception e) { return ""; }
    }
}
