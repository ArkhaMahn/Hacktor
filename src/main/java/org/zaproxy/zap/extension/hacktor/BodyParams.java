package org.zaproxy.zap.extension.hacktor;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Body-parameter detection and rewriting that works "no matter the content type": it
 * parses application/x-www-form-urlencoded, multipart/form-data, JSON, XML and falls
 * back to an opaque single "body" parameter for anything else (including empty or
 * unusual Content-Type headers). Each detected parameter knows its exact char span in
 * the original body, so {@link #rewrite} can replace / append / prepend the payload
 * value in-place, keeping the surrounding format untouched.
 */
public final class BodyParams {

    public static final class Param {
        public final String name;      // display path, e.g. "user.email", "[0]", "id", "body"
        public final String kind;      // form | json | xml | multipart | text
        public final boolean quoted;   // JSON: value token is a double-quoted string
        public final int valueStart;   // char index of the value content in the original body
        public final int valueEnd;     // char index just past the value content
        public final String value;     // original value (decoded for JSON/xml)

        Param(String name, String kind, boolean quoted, int valueStart, int valueEnd, String value) {
            this.name = name;
            this.kind = kind;
            this.quoted = quoted;
            this.valueStart = valueStart;
            this.valueEnd = valueEnd;
            this.value = value;
        }
    }

    private BodyParams() {}

    private static final Pattern BOUNDARY_PATTERN =
        Pattern.compile("boundary=\"?([^;\"]+)\"?");
    private static final Pattern MULTIPART_NAME_PATTERN =
        Pattern.compile("name=\"([^\"]*)\"");

    /** Content-type of a request, lower-cased and without parameters/boundary. */
    public static String contentType(HttpMessage msg) {
        String ct = msg.getRequestHeader().getHeader("Content-Type");
        if (ct == null) return "";
        int semi = ct.indexOf(';');
        return (semi >= 0 ? ct.substring(0, semi) : ct).trim().toLowerCase();
    }

    /** Boundary value from a multipart Content-Type, or null. */
    private static String boundaryOf(HttpMessage msg) {
        String ct = msg.getRequestHeader().getHeader("Content-Type");
        if (ct == null) return null;
        Matcher m = BOUNDARY_PATTERN.matcher(ct);
        return m.find() ? m.group(1) : null;
    }

    /**
     * Detects the body parameters of a request, dispatching on the Content-Type so
     * testing works no matter which envelope the API expects. A non-empty body that
     * cannot be parsed as its declared type is treated as a single opaque parameter.
     */
    public static List<Param> extract(HttpMessage msg) {
        List<Param> out = new ArrayList<>();
        if (msg.getRequestBody() == null) return out;
        String body = msg.getRequestBody().toString();
        if (body == null || body.isEmpty()) return out;

        String ct = contentType(msg);
        if (ct.contains("x-www-form-urlencoded")) {
            return parseForm(body);
        }
        if (ct.contains("multipart/form-data")) {
            String boundary = boundaryOf(msg);
            if (boundary != null && !boundary.isEmpty() && boundary.length() >= 2) {
                List<Param> parts = parseMultipart(body, boundary);
                if (!parts.isEmpty()) return parts;
            }
            return textParam(body);
        }
        if (ct.contains("json") || ct.contains("+json")) {
            List<Param> json = new ArrayList<>();
            try {
                parseJson(body, json);
            } catch (Exception ignored) {}
            if (!json.isEmpty()) return json;
            return textParam(body);
        }
        if (ct.contains("xml") || ct.contains("+xml")) {
            List<Param> xml = new ArrayList<>();
            try {
                parseXml(body, xml);
            } catch (Exception ignored) {}
            if (!xml.isEmpty()) return xml;
            return textParam(body);
        }
        // Unknown / missing Content-Type: whole body is one opaque parameter.
        return textParam(body);
    }

    /** True when a new parameter can be appended to the body for this kind. */
    public static boolean canInject(Param p) {
        return "form".equals(p.kind) || "json".equals(p.kind);
    }

    /**
     * Rewrites the body with the payload applied to the target parameter.
     * {@code mode} is one of REPLACE, APPEND, PREPEND, INJECT (INJECT adds a new
     * "hacktor" parameter and returns the body unchanged when the format cannot carry
     * one).
     */
    public static String rewrite(HttpMessage msg, Param p, String payload, String mode) {
        if (msg.getRequestBody() == null || p == null) return null;
        String body = msg.getRequestBody().toString();
        if (body == null) return null;
        String op = mode == null ? "REPLACE" : mode;
        try {
            switch (p.kind) {
                case "form":
                    return rewriteForm(body, p, payload, op);
                case "json":
                    return rewriteJson(body, p, payload, op);
                case "xml":
                    return rewriteXml(body, p, payload, op);
                case "multipart":
                    return rewriteSpan(body, p, payload, op);
                case "text":
                    return rewriteText(body, payload, op);
                default:
                    return body;
            }
        } catch (Exception e) {
            return body;
        }
    }

    // ── form-urlencoded ──────────────────────────────────────────────────

    private static List<Param> parseForm(String body) {
        List<Param> out = new ArrayList<>();
        int n = body.length();
        int i = 0;
        while (i < n) {
            int amp = body.indexOf('&', i);
            int end = amp < 0 ? n : amp;
            int eq = body.indexOf('=', i);
            if (eq < 0 || eq > end) eq = -1;
            String key = (eq >= 0) ? body.substring(i, eq) : body.substring(i, end);
            int vs = (eq >= 0) ? eq + 1 : end;
            String val = body.substring(vs, end);
            out.add(new Param(key, "form", true, vs, end, val));
            i = end + 1;
        }
        return out;
    }

    // ── multipart/form-data ──────────────────────────────────────────────

    private static List<Param> parseMultipart(String body, String boundary) {
        List<Param> out = new ArrayList<>();
        String delim = "--" + boundary;
        int idx = body.indexOf(delim);
        while (idx >= 0) {
            int headStart = idx + delim.length();
            while (headStart < body.length()
                    && (body.charAt(headStart) == '\r' || body.charAt(headStart) == '\n')) {
                headStart++;
            }
            int sep = body.indexOf("\r\n\r\n", headStart);
            int sepLen = 4;
            if (sep < 0) {
                sep = body.indexOf("\n\n", headStart);
                sepLen = 2;
            }
            if (sep < 0) break;
            String head = body.substring(headStart, sep);
            int vs = sep + sepLen;
            int nextDelim = body.indexOf("\r\n" + delim, vs);
            if (nextDelim < 0) nextDelim = body.indexOf("\n" + delim, vs);
            int ve = (nextDelim < 0) ? body.length() : nextDelim;
            Matcher m = MULTIPART_NAME_PATTERN.matcher(head);
            if (m.find()) {
                String name = m.group(1);
                out.add(new Param(name, "multipart", true, vs, ve, body.substring(vs, ve)));
            }
            idx = nextDelim < 0 ? -1 : nextDelim;
            // advance past the delimiter for the next iteration
            if (idx >= 0) {
                int dl = body.indexOf(delim, idx + 2);
                idx = dl < 0 ? -1 : dl;
            }
        }
        return out;
    }

    // ── JSON (minimal recursive-descent tree over the raw body) ──────────

    private static void parseJson(String body, List<Param> out) {
        parseJsonValue(body, 0, "", out);
    }

    private static int parseJsonValue(String body, int pos, String path, List<Param> out) {
        pos = skipWs(body, pos);
        int n = body.length();
        if (pos >= n) return pos;
        char c = body.charAt(pos);
        if (c == '{') return parseJsonObject(body, pos + 1, path, out, n);
        if (c == '[') return parseJsonArray(body, pos + 1, path, out, n);
        if (c == '"') {
            int close = findStringEnd(body, pos + 1);
            if (close < 0) return n;
            String raw = body.substring(pos, close + 1);
            out.add(new Param(path, "json", true, pos + 1, close, unescapeJson(raw)));
            return close + 1;
        }
        int end = pos;
        while (end < n && body.charAt(end) != ',' && body.charAt(end) != '}'
                && body.charAt(end) != ']' && body.charAt(end) != '\n'
                && body.charAt(end) != '\r' && body.charAt(end) != ' '
                && body.charAt(end) != '\t') {
            end++;
        }
        out.add(new Param(path, "json", false, pos, end, body.substring(pos, end)));
        return end;
    }

    private static int parseJsonObject(String body, int pos, String path, List<Param> out, int n) {
        while (pos < n) {
            pos = skipWs(body, pos);
            if (pos >= n) break;
            char c = body.charAt(pos);
            if (c == '}') return pos + 1;
            if (c == '"') {
                int keyEnd = findStringEnd(body, pos + 1);
                if (keyEnd < 0) return n;
                String key = unescapeJson(body.substring(pos + 1, keyEnd));
                pos = skipWs(body, keyEnd + 1);
                if (pos < n && body.charAt(pos) == ':') pos = skipWs(body, pos + 1);
                String child = path.isEmpty() ? key : path + "." + key;
                pos = parseJsonValue(body, pos, child, out);
            } else {
                pos++;
            }
            pos = skipWs(body, pos);
            if (pos < n && body.charAt(pos) == ',') pos++;
        }
        return n;
    }

    private static int parseJsonArray(String body, int pos, String path, List<Param> out, int n) {
        int i = 0;
        while (pos < n) {
            pos = skipWs(body, pos);
            if (pos >= n) break;
            char c = body.charAt(pos);
            if (c == ']') return pos + 1;
            pos = parseJsonValue(body, pos, path + "[" + i + "]", out);
            i++;
            pos = skipWs(body, pos);
            if (pos < n && body.charAt(pos) == ',') pos++;
        }
        return n;
    }

    private static int skipWs(String body, int pos) {
        int n = body.length();
        while (pos < n) {
            char c = body.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            pos++;
        }
        return pos;
    }

    private static int findStringEnd(String body, int from) {
        int n = body.length();
        for (int i = from; i < n; i++) {
            char c = body.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') return i;
        }
        return -1;
    }

    private static String unescapeJson(String token) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c == '\\' && i + 1 < token.length()) {
                char n = token.charAt(++i);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case '/': sb.append('/'); break;
                    case '\\': sb.append('\\'); break;
                    case '"': sb.append('"'); break;
                    case 'u':
                        if (i + 4 < token.length()) {
                            sb.append((char) Integer.parseInt(token.substring(i + 1, i + 5), 16));
                            i += 4;
                        }
                        break;
                    default: sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    // ── XML ──────────────────────────────────────────────────────────────

    private static void parseXml(String body, List<Param> out) throws Exception {
        Document doc = parseXmlDoc(body);
        if (doc == null) return;
        walkXml(doc.getDocumentElement(), "", out);
    }

    private static void walkXml(Element el, String path, List<Param> out) {
        String here = path.isEmpty() ? el.getTagName() : path + "." + el.getTagName();
        boolean hasChildren = false;
        NodeList kids = el.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            if (kids.item(i).getNodeType() == Node.ELEMENT_NODE) {
                hasChildren = true;
                walkXml((Element) kids.item(i), here, out);
            }
        }
        if (!hasChildren) {
            String val = el.getTextContent() == null ? "" : el.getTextContent();
            out.add(new Param(here, "xml", true, 0, 0, val));
        }
    }

    private static Element findXmlByPath(Document doc, String path) {
        if (doc.getDocumentElement() == null) return null;
        String[] parts = path.split("\\.");
        Element cur = null;
        NodeList list = doc.getElementsByTagName(parts[0]);
        if (list.getLength() == 0) return null;
        cur = (Element) list.item(0);
        for (int i = 1; i < parts.length; i++) {
            NodeList kids = cur.getChildNodes();
            Element found = null;
            for (int j = 0; j < kids.getLength(); j++) {
                Node n = kids.item(j);
                if (n.getNodeType() == Node.ELEMENT_NODE
                        && n.getNodeName().equals(parts[i])) {
                    found = (Element) n;
                    break;
                }
            }
            if (found == null) return null;
            cur = found;
        }
        return cur;
    }

    private static String rewriteXml(String body, Param p, String payload, String op) throws Exception {
        Document doc = parseXmlDoc(body);
        if (doc == null) return body;
        Element el = findXmlByPath(doc, p.name);
        if (el == null) return body;
        String old = el.getTextContent() == null ? "" : el.getTextContent();
        String next;
        switch (op) {
            case "REPLACE": next = payload; break;
            case "APPEND":  next = old + payload; break;
            case "PREPEND": next = payload + old; break;
            default:        next = old; break;
        }
        el.setTextContent(next);
        return serializeXml(doc);
    }

    private static Document parseXmlDoc(String body) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            // Never let a hostile request body spawn entities / DTDs inside our parser.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
            try {
                factory.setAttribute(
                    "http://javax.xml.XMLConstants/property/accessExternalDTD", "");
                factory.setAttribute(
                    "http://javax.xml.XMLConstants/property/accessExternalSchema", "");
            } catch (IllegalArgumentException unsupportedJdk) {
                // Older JDKs reject these constants; the disallow-doctype flag above
                // still blocks the classic XXE vectors.
            }
        } catch (Exception ignored) {}
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new org.xml.sax.InputSource(new StringReader(body)));
    }

    private static String serializeXml(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        t.setOutputProperty(OutputKeys.INDENT, "no");
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    // ── generic helpers ──────────────────────────────────────────────────

    /** Whole-body opaque parameter for unknown / malformed content types. */
    private static List<Param> textParam(String body) {
        List<Param> out = new ArrayList<>();
        out.add(new Param("body", "text", true, 0, body.length(), body));
        return out;
    }

    private static String rewriteSpan(String body, Param p, String payload, String op) {
        int vs = Math.max(0, Math.min(p.valueStart, body.length()));
        int ve = Math.min(Math.max(vs, p.valueEnd), body.length());
        String old = body.substring(vs, ve);
        String next;
        switch (op) {
            case "REPLACE": next = payload; break;
            case "APPEND":  next = old + payload; break;
            case "PREPEND": next = payload + old; break;
            default:        next = old; break;
        }
        return body.substring(0, vs) + next + body.substring(ve);
    }

    private static String rewriteText(String body, String payload, String op) {
        switch (op) {
            case "REPLACE": return payload;
            case "APPEND":  return body + payload;
            case "PREPEND": return payload + body;
            default:        return body;
        }
    }

    private static String rewriteForm(String body, Param p, String payload, String op) {
        if ("INJECT".equals(op)) {
            return body + "&hacktor=" + payload;
        }
        return rewriteSpan(body, p, payload, op);
    }

    private static String rewriteJson(String body, Param p, String payload, String op) {
        if ("INJECT".equals(op)) {
            int close = body.lastIndexOf('}');
            // only valid when the body is a JSON object
            if (close < 0 || body.indexOf('{') > close) return body;
            return body.substring(0, close) + ",\"hacktor\":\""
                + jsonEscape(payload) + "\"" + body.substring(close);
        }
        int vs = Math.max(0, Math.min(p.valueStart, body.length()));
        int ve = Math.min(Math.max(vs, p.valueEnd), body.length());
        String old = body.substring(vs, ve);
        String content;
        switch (op) {
            case "REPLACE": content = jsonEscape(payload); break;
            case "APPEND":  content = jsonEscape(old) + jsonEscape(payload); break;
            case "PREPEND": content = jsonEscape(payload) + jsonEscape(old); break;
            default:        content = old; break;
        }
        String replacement = p.quoted ? content : "\"" + content + "\"";
        return body.substring(0, vs) + replacement + body.substring(ve);
    }
}