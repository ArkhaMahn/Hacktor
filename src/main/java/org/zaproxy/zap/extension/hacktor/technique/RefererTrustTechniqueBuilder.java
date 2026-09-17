package org.zaproxy.zap.extension.hacktor.technique;

import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;

/**
 * Referer-based access-control trust bypasses.
 *
 * <p>Some applications enforce denylists only against direct access; pages
 * reached by clicking a link from an "internal" surface (admin/dashboard)
 * are exempt. Probes set {@code Referer} to plausible trusted origins.
 *
 * <p>Sub-techniques:
 * <ul>
 *   <li><b>Classic</b> — Referer set to {@code <host>/admin}, {@code /dashboard},
 *       {@code /internal} on the same scheme/host.</li>
 *   <li><b>Rare</b> — Referer pointing to localhost / 127.0.0.1 internal
 *       addresses; Referer to a different subdomain ({@code} admin.target /
 *       internal.target) — common on multi-tenant SSO setups that trust the
 *       parent domain; Referer to {@code about:blank} and {@code data:} URIs.</li>
 *   <li><b>Novel</b> — Referer with embedded credentials
 *       ({@code https://admin:admin@target/...}), Referer chains that include
 *       path-traversal segments ({@code /admin/../admin}), Referer pointing
 *       at the protected path itself ({@code <host><protectedPath>}) so any
 *       substring check passes, and Referer using same-origin encoded
 *       variants ({@code https://%74arget/<path>}).</li>
 * </ul>
 */
public class RefererTrustTechniqueBuilder extends AbstractTechniqueBuilder {

    @Override public String getFamily() { return "Referer Trust"; }

    @Override public int getOrder() { return 61; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {

        String host = extractHost(ctx.origPath);
        if (host == null || host.isEmpty()) {
            host = "https://target.local";
        }
        final String finalHost = host;
        String hostNoScheme = stripScheme(host);
        String baseNoScheme = (ctx.baseClean == null || ctx.baseClean.isEmpty())
            ? "/admin" : ctx.baseClean;

        // ── Classic — same-host internal path ───────────────────────────
        String[] classicValues = {"admin", "dashboard", "internal", "login",
            "home", "index", "portal", "console"};
        for (String rv : classicValues) {
            final String referer = finalHost + "/" + rv;
            techs.add(new Technique(getFamily(),
                "RefererSameHost:" + rv,
                "Referer pointing at same-host /" + rv,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", referer); return c; }));
        }

        // ── Rare — localhost / loopback referer ─────────────────────────
        String[] localhostValues = {
            "http://127.0.0.1/admin",
            "http://127.0.0.1:80/admin",
            "http://localhost/admin",
            "http://[::1]/admin",
            "http://127.1/admin",
            "http://127.0.0.1:8080/admin",
            "http://localhost.localdomain/admin"
        };
        for (String ref : localhostValues) {
            final String r = ref;
            techs.add(new Technique(getFamily(),
                "RefererLocalhost:" + ref.replace(":", "_").replace("[", "_").replace("]", "_"),
                "Referer pointing at loopback: " + ref,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }

        // ── Rare — sibling-subdomain referer ────────────────────────────
        // Multi-tenant SSO / shared-platform setups often whitelist the
        // parent domain. admin.<host>, internal.<host>, etc. resolve to
        // a different IP but pass a suffix allowlist.
        String[] subdomains = {"admin", "internal", "intranet", "portal",
            "staging", "dev", "test", "private", "secure", "mgmt"};
        for (String sub : subdomains) {
            final String referer = "https://" + sub + "." + hostNoScheme + "/";
            techs.add(new Technique(getFamily(),
                "RefererSubdomain:" + sub,
                "Referer pointing at sibling subdomain: " + sub + "." + hostNoScheme,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", referer); return c; }));
        }

        // ── Rare — same-origin with leading/trailing whitespace ─────────
        // Header parsers may strip whitespace before equality checks,
        // but the protection logic may not.
        String[] whitespace = {
            " " + finalHost + "/admin",
            finalHost + "/admin ",
            "\t" + finalHost + "/admin",
            finalHost + "/admin\r\nX-Injected: yes"
        };
        for (String ref : whitespace) {
            final String r = ref;
            markRawAdd(techs, new Technique(getFamily(),
                "RefererWhitespace:" + ref.replace(" ", "_S").replace("\t", "_T").replace("\r", "_CR").replace("\n", "_LF"),
                "Referer with whitespace injection: '" + ref.replace("\r", "\\r").replace("\n", "\\n") + "'",
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }

        // ── Rare — Referer of special schemes ───────────────────────────
        String[] schemes = {"about:blank", "data:text/html,", "javascript:void(0)",
            "file:///etc/passwd", "null"};
        for (String ref : schemes) {
            final String r = ref;
            techs.add(new Technique(getFamily(),
                "RefererScheme:" + ref.replace(":", "_").replace("/", "_"),
                "Referer with special scheme: " + ref,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }

        // ── Novel — Referer pointing at the protected path itself ───────
        // Some substring / same-origin checks only check if the protected
        // path appears anywhere in the Referer header value.
        final String selfPath = baseNoScheme;
        final String selfRef = finalHost + selfPath;
        techs.add(new Technique(getFamily(),
            "RefererSelfPath",
            "Referer pointing at the protected path itself (substring check bypass)",
            base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", selfRef); return c; }));

        // ── Novel — Referer with embedded userinfo ──────────────────────
        String[] userinfoValues = {
            "https://admin:admin@" + hostNoScheme + "/",
            "https://root:root@" + hostNoScheme + "/admin",
            "https://user:password@" + hostNoScheme + "/dashboard"
        };
        for (String ref : userinfoValues) {
            final String r = ref;
            markRawAdd(techs, new Technique(getFamily(),
                "RefererUserinfo:" + ref.replace(":", "_").replace("@", "_AT_"),
                "Referer with embedded userinfo: " + ref,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }

        // ── Novel — Referer with traversal segments ──────────────────────
        String[] traversalRefs = {
            host + "/admin/../" + stripLeadingSlash(baseNoScheme),
            host + "/dashboard/../admin/" + stripLeadingSlash(baseNoScheme),
            host + "/admin/%2e%2e/" + stripLeadingSlash(baseNoScheme),
            host + "/admin/..%2f" + stripLeadingSlash(baseNoScheme)
        };
        for (String ref : traversalRefs) {
            final String r = ref;
            techs.add(new Technique(getFamily(),
                "RefererTraversal",
                "Referer with traversal segments: " + ref,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }

        // ── Novel — Referer pointing at encoded variant of host ─────────
        // e.g. https://%74arget/ or https://target%2e.com/ — substring
        // checks may accept these; origin checks should not.
        String[] encodedHosts = {
            "https://%61dmin." + hostNoScheme + "/",
            "https://" + hostNoScheme.replace(".", "%2e") + "/",
            "https://" + hostNoScheme.replace("a", "%61") + "/",
        };
        for (String ref : encodedHosts) {
            final String r = ref;
            markRawAdd(techs, new Technique(getFamily(),
                "RefererEncodedHost",
                "Referer with encoded host chars: " + ref,
                base -> { HttpMessage c = cloneMsg(base); addHeader(c, "Referer", r); return c; }));
        }
    }

    private static String extractHost(String anyUrlish) {
        if (anyUrlish == null) return null;
        int scheme = anyUrlish.indexOf("://");
        if (scheme < 0) return null;
        int pathStart = anyUrlish.indexOf('/', scheme + 3);
        if (pathStart < 0) return anyUrlish;
        return anyUrlish.substring(0, pathStart);
    }

    private static String stripScheme(String url) {
        if (url == null) return "";
        int idx = url.indexOf("://");
        return idx < 0 ? url : url.substring(idx + 3);
    }

    private static String stripLeadingSlash(String path) {
        if (path == null || path.length() <= 1) return "";
        return path.charAt(0) == '/' ? path.substring(1) : path;
    }
}