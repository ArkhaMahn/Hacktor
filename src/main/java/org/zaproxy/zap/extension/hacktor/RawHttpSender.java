package org.zaproxy.zap.extension.hacktor;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.SSLConnector;

/**
 * Minimal raw-socket HTTP sender used to transmit requests whose request-target
 * carries a literal {@code #} fragment.
 *
 * <p>ZAP's normal {@code HttpSender} (via commons-httpclient
 * {@code HttpMethodBase.setURI}) deliberately builds the wire request line from
 * {@code getEscapedPath()} + {@code getEscapedQuery()} only, so any fragment set on
 * the in-memory {@link URI} is silently dropped before the socket write. For
 * fragment-deception techniques to actually reach the web server / reverse proxy we
 * must serialise the request line ourselves and write it over a raw socket.</p>
 *
 * <p>This sender is intentionally best-effort: on any failure it returns
 * {@code false} and leaves the message untouched, so callers can fall back to the
 * normal {@code HttpSender} without breaking the rest of the add-on.</p>
 */
public final class RawHttpSender {

    private static final class SslHolder {
        static final SSLConnector INSTANCE = new SSLConnector();
    }

    /** Hard caps on the bytes read from a response so a hostile or garbled server
     *  (huge Content-Length, endless chunk stream, never-ending header, no-framing
     *  body) cannot balloon the add-on's heap. Responses beyond these are truncated. */
    private static final int MAX_RESPONSE_HEADER = 64 * 1024;
    private static final int MAX_RESPONSE_BODY = 8 * 1024 * 1024;

    /** Bulk read block so large capped reads do not hammer the stream one byte at a
     *  time (which could exceed the socket read timeout before reaching the cap). */
    private static final int CHUNK = 16 * 1024;

    /** Reads up to {@code buf.length} bytes into {@code buf}, looping over partial
     *  reads. Returns the count read, or -1 on EOF with nothing read. */
    private static int readSome(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total == 0 ? -1 : total;
    }

    private RawHttpSender() {
    }

    /**
     * Sends {@code msg} over a raw socket, preserving any literal {@code #} in the
     * request-target. On success the response is parsed into {@code msg.getResponseHeader()}
     * / {@code getResponseBody()}. Returns {@code false} on any error.
     */
    public static boolean send(HttpMessage msg) {
        return send(msg, -1);
    }

    /**
     * Sends {@code msg} over a raw socket using {@code timeoutSecs} for both the connect
     * and read timeouts. When {@code timeoutSecs <= 0} the timeout configured in ZAP's
     * connection options is used. Otherwise behaves exactly like {@link #send(HttpMessage)}.
     */
    public static boolean send(HttpMessage msg, int timeoutSecs) {
        HttpRequestHeader req = msg.getRequestHeader();
        if (req == null || req.getURI() == null) {
            return false;
        }
        try {
            URI uri = req.getURI();

            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            String host = uri.getHost();
            int port = uri.getPort();
            if (port <= 0) {
                port = secure ? 443 : 80;
            }
            if (host == null || host.isEmpty()) {
                return false;
            }

            byte[] raw = buildRequestBytes(msg, uri, secure);
            if (raw == null) {
                return false;
            }

            ConnectionParam conn =
                Model.getSingleton().getOptionsParam().getConnectionParam();
            int timeout = Math.max(conn == null ? 10 : conn.getTimeoutInSecs(), 1);
            if (timeoutSecs > 0) {
                timeout = timeoutSecs;
            }

            Socket socket = null;
            InputStream in = null;
            OutputStream out = null;
            try {
                // Route through the configured outbound proxy when enabled for host.
                if (conn != null && conn.isUseProxyChain() && conn.isUseProxy(host)) {
                    String proxyHost = conn.getProxyChainName();
                    int proxyPort = conn.getProxyChainPort();
                    socket = new Socket();
                    socket.connect(
                        new InetSocketAddress(proxyHost, proxyPort), timeout * 1000);
                    if (secure) {
                        Socket ssl = SslHolder.INSTANCE.createSocket(socket, host, port, true);
                        socket = ssl;
                    }
                } else {
                    if (secure) {
                        socket = SslHolder.INSTANCE.createSocket(host, port);
                    } else {
                        socket = new Socket();
                        socket.connect(
                            new InetSocketAddress(host, port), timeout * 1000);
                    }
                }
                socket.setSoTimeout(timeout * 1000);
                out = socket.getOutputStream();
                Instant reqSent = Instant.now();
                out.write(raw);
                out.flush();

                in = new BufferedInputStream(socket.getInputStream());
                byte[] response = readResponse(in);
                if (response == null) {
                    return false;
                }
                parseResponse(msg, response);
                Instant resRecv = Instant.now();
                // Side-channel timing so callers (runOne) can surface request/send
                // and response/receive timestamps. Stripped by the caller after reading.
                DateTimeFormatter fmt = DateTimeFormatter.ofPattern("HH:mm:ss")
                    .withZone(ZoneOffset.UTC);
                String reqTs = fmt.format(reqSent);
                String resTs = fmt.format(resRecv);
                try {
                    msg.getRequestHeader().setHeader("X-Hacktor-Timing",
                        "req=" + reqTs + ";res=" + resTs);
                } catch (Exception ignored) {}
                return true;
            } finally {
                if (out != null) {
                    try { out.close(); } catch (Exception ignored) {}
                }
                if (in != null) {
                    try { in.close(); } catch (Exception ignored) {}
                }
                if (socket != null) {
                    try { socket.close(); } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] buildRequestBytes(HttpMessage msg, URI uri, boolean secure) {
        StringBuilder sb = buildRequestHead(msg, uri, secure);
        if (sb == null) {
            return null;
        }

        StringBuilder full = sb;
        byte[] body = msg.getRequestBody().getBytes();
        if (body != null && body.length > 0) {
            byte[] head = full.toString().getBytes(StandardCharsets.ISO_8859_1);
            byte[] raw = new byte[head.length + body.length];
            System.arraycopy(head, 0, raw, 0, head.length);
            System.arraycopy(body, 0, raw, head.length, body.length);
            return raw;
        }
        return full.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * Builds the exact request bytes that would be written to the wire for {@code msg},
     * mirroring {@link #send(HttpMessage)} (origin-form direct / absolute-form via proxy,
     * literal {@code #fragment} preserved). Returns {@code null} if the message cannot be
     * serialised. Used by the Results view so the displayed request matches what is actually
     * sent, including for asterisk/authority/absolute-form and malformed request lines.
     */
    public static byte[] toWireBytes(HttpMessage msg) {
        HttpRequestHeader req = msg.getRequestHeader();
        if (req == null || req.getURI() == null) {
            return null;
        }
        try {
            URI uri = req.getURI();
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            StringBuilder sb = buildRequestHead(msg, uri, secure);
            if (sb == null) {
                return null;
            }
            StringBuilder full = sb;
            byte[] body = msg.getRequestBody().getBytes();
            if (body != null && body.length > 0) {
                byte[] head = full.toString().getBytes(StandardCharsets.ISO_8859_1);
                byte[] raw = new byte[head.length + body.length];
                System.arraycopy(head, 0, raw, 0, head.length);
                System.arraycopy(body, 0, raw, head.length, body.length);
                return raw;
            }
            return full.toString().getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    private static StringBuilder buildRequestHead(HttpMessage msg, URI uri, boolean secure) {
        StringBuilder sb = new StringBuilder(384);

        String method = msg.getRequestHeader().getMethod();
        if (method == null || method.isEmpty()) {
            method = "GET";
        }
        String version = msg.getRequestHeader().getVersion();
        if (version == null || version.isEmpty()) {
            version = "HTTP/1.1";
        }

        // Some techniques need a literal path on the wire (e.g. Padding with %20,
        // Backslash/UNC paths) that URI.setPath() would re-encode. They mark the
        // path with a request attribute (non-header) and we honour it here, then
        // strip it before serialising the rest of the headers.
        String wirePath = msg.getRequestHeader().getHeader("X-Hacktor-WirePath");

        String target;
        if (wirePath != null && !wirePath.isEmpty()) {
            target = wirePath;
        } else {
            target = buildRequestTarget(uri, secure);
            if (target == null) {
                return null;
            }
        }

        sb.append(method).append(' ').append(target).append(' ').append(version).append("\r\n");

        String headers = msg.getRequestHeader().getHeadersAsString();
        if (headers != null) {
            int firstCrlf = headers.indexOf("\r\n");
            String block = (firstCrlf >= 0) ? headers.substring(firstCrlf + 2) : headers;
            // Skip the request line only; keep the rest verbatim, minus the wire-path
            // and timing markers (both are display/measurement side channels only).
            if (wirePath != null) {
                block = stripHeaderLine(block, "X-Hacktor-WirePath:");
                if (block == null) block = "";
            }
            block = stripHeaderLine(block, "X-Hacktor-Timing:");
            if (block == null) block = "";
            sb.append(block);
        }
        if (sb.charAt(sb.length() - 1) != '\n') {
            sb.append("\r\n");
        }
        sb.append("\r\n");
        return sb;
    }

    private static String stripHeaderLine(String block, String prefix) {
        int idx = 0;
        while (true) {
            int next = block.indexOf(prefix, idx);
            if (next < 0) return block;
            // Must be at start of line
            if (next == 0 || block.charAt(next - 1) == '\n') {
                int lineEnd = block.indexOf('\n', next);
                if (lineEnd < 0) return block.substring(0, next);
                // also trim preceding \r
                int start = next;
                if (start > 0 && block.charAt(start - 1) == '\r') start--;
                return block.substring(0, start) + block.substring(lineEnd + 1);
            }
            idx = next + 1;
        }
    }

    /**
     * Builds the request-target. Origin-form for direct sends; absolute-form for
     * proxy sends. A literal {@code #fragment} is preserved at the end so it
     * reaches the wire unchanged.
     */
    private static String buildRequestTarget(URI uri, boolean secure) {
        try {
            StringBuilder target = new StringBuilder(256);

            ConnectionParam conn =
                Model.getSingleton().getOptionsParam().getConnectionParam();
            boolean proxyForm = conn != null && conn.isUseProxyChain()
                && conn.isUseProxy(uri.getHost());

            if (proxyForm) {
                target.append(secure ? "https" : "http").append("://")
                      .append(uri.getHost());
                int p = uri.getPort();
                if (p <= 0) p = secure ? 443 : 80;
                target.append(':').append(p);
            }

            // Detect absolute-form path: after replacePath with an absolute-form URI, the URI's
            // toString() holds the exact literal string (brackets, casing preserved) and
            // getEscapedPath() returns just the path. Use toString() to send the absolute
            // form as the request-target exactly as the technique intended.
            // Detect absolute-form URI stored as the path: after replacePath with
            // "http://[::1]/admin/panel", uri.getPath() (unescaped) contains "://" while
            // uri.getEscapedPath() would return the path component only. Use the unescaped
            // path to preserve literal brackets in the wire request-target.
            String path = uri.getEscapedPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            String unescapedPath = uri.getPath();
            if (unescapedPath != null && unescapedPath.contains("://")) {
                // Absolute-form stored as path: use the unescaped literal form.
                target.append(unescapedPath);
            } else if (proxyForm) {
                if (path.startsWith("/")) {
                    target.append(path);
                } else {
                    target.append('/').append(path);
                }
            } else {
                target.append(path);
            }
            String query = uri.getEscapedQuery();
            if (query != null && !query.isEmpty()) {
                target.append('?').append(query);
            }

            if (uri.hasFragment()) {
                String frag = uri.getEscapedFragment();
                if (frag != null) {
                    target.append('#').append(frag);
                }
            }
            return target.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readResponse(InputStream in) throws IOException {
        // Read status line + headers, in chunks so large headers cannot stall
        // the socket timeout while being read one byte at a time.
        StringBuilder head = new StringBuilder(1024);
        byte[] buf = new byte[CHUNK];
        boolean seenHeaderEnd = false;
        while (!seenHeaderEnd) {
            int n = readSome(in, buf);
            if (n <= 0) {
                return head.length() == 0 ? null
                    : head.toString().getBytes(StandardCharsets.ISO_8859_1);
            }
            for (int i = 0; i < n && !seenHeaderEnd; i++) {
                head.append((char) (buf[i] & 0xFF));
                if (head.length() >= MAX_RESPONSE_HEADER) {
                    // Header grew past the cap: stop reading headers and treat what we
                    // have as the whole (truncated) response so the read terminates.
                    seenHeaderEnd = true;
                    break;
                }
                if (head.length() >= 4) {
                    int L = head.length();
                    if (head.charAt(L - 1) == '\n'
                        && head.charAt(L - 2) == '\r'
                        && head.charAt(L - 3) == '\n'
                        && head.charAt(L - 4) == '\r') {
                        seenHeaderEnd = true;
                    }
                }
            }
        }
        String headerText = head.toString();

        long len = getContentLength(headerText);
        boolean chunked = hasHeader(headerText, "Transfer-Encoding")
            && headerText.toLowerCase(Locale.ROOT).contains("chunked");

        StringBuilder body;
        if (chunked) {
            body = readChunked(in);
        } else if (len >= 0) {
            body = readFixed(in, len);
        } else {
            // No framing: read until EOF (legacy 1.0 style), capped.
            body = new StringBuilder();
            int n;
            while (body.length() < MAX_RESPONSE_BODY && (n = readSome(in, buf)) > 0) {
                int take = Math.min(n, MAX_RESPONSE_BODY - body.length());
                for (int i = 0; i < take; i++) {
                    body.append((char) (buf[i] & 0xFF));
                }
            }
        }
        return (headerText + body.toString()).getBytes(StandardCharsets.ISO_8859_1);
    }

    private static StringBuilder readFixed(InputStream in, long len) throws IOException {
        long limit = Math.min(len, MAX_RESPONSE_BODY);
        StringBuilder sb = new StringBuilder((int) Math.min(limit, 1_048_576));
        long remaining = limit;
        byte[] buf = new byte[CHUNK];
        while (remaining > 0) {
            int n = readSome(in, buf);
            if (n <= 0) {
                break;
            }
            int take = (int) Math.min(n, remaining);
            for (int i = 0; i < take; i++) {
                sb.append((char) (buf[i] & 0xFF));
            }
            remaining -= take;
        }
        return sb;
    }

    private static StringBuilder readChunked(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder(4096);
        while (sb.length() < MAX_RESPONSE_BODY) {
            String sizeLine = readLine(in);
            if (sizeLine == null) {
                break;
            }
            String trim = sizeLine.trim();
            int semi = trim.indexOf(';');
            if (semi >= 0) {
                trim = trim.substring(0, semi);
            }
            int chunkSize;
            try {
                chunkSize = Integer.parseInt(trim.trim(), 16);
            } catch (NumberFormatException e) {
                break;
            }
            if (chunkSize == 0) {
                // trailers
                while (true) {
                    String tl = readLine(in);
                    if (tl == null || tl.isEmpty()) {
                        break;
                    }
                }
                break;
            }
            long toRead = Math.min(chunkSize, (long) MAX_RESPONSE_BODY - sb.length());
            byte[] buf = new byte[CHUNK];
            long have = 0;
            while (have < toRead) {
                int n = readSome(in, buf);
                if (n <= 0) {
                    return sb;
                }
                int take = (int) Math.min(n, toRead - have);
                for (int i = 0; i < take; i++) {
                    sb.append((char) (buf[i] & 0xFF));
                }
                have += take;
            }
            if (sb.length() >= MAX_RESPONSE_BODY) {
                break;
            }
            // trailing CRLF after chunk data
            in.read();
            in.read();
        }
        return sb;
    }

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder(80);
        int b;
        while ((b = in.read()) >= 0) {
            if (b == '\n') {
                break;
            }
            if (b != '\r' && sb.length() < 8192) {
                sb.append((char) b);
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private static long getContentLength(String headerText) {
        int idx = indexOfHeaderIgnoreCase(headerText, "Content-Length:");
        if (idx < 0) {
            return -1;
        }
        int lineEnd = headerText.indexOf('\n', idx);
        if (lineEnd < 0) {
            lineEnd = headerText.length();
        }
        String val = headerText.substring(idx + "Content-Length:".length(), lineEnd)
            .trim();
        try {
            return Long.parseLong(val);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static boolean hasHeader(String headerText, String name) {
        return indexOfHeaderIgnoreCase(headerText, name + ":") >= 0;
    }

    private static int indexOfHeaderIgnoreCase(String text, String headerPrefix) {
        String lower = text.toLowerCase(Locale.ROOT);
        String needle = headerPrefix.toLowerCase(Locale.ROOT);
        int from = 0;
        while (true) {
            int i = lower.indexOf(needle, from);
            if (i < 0) {
                return -1;
            }
            // Ensure it's at the start of a line.
            if (i == 0 || lower.charAt(i - 1) == '\n') {
                return i;
            }
            from = i + 1;
        }
    }

    private static void parseResponse(HttpMessage msg, byte[] responseBytes)
            throws org.parosproxy.paros.network.HttpMalformedHeaderException {
        String raw = new String(responseBytes, StandardCharsets.ISO_8859_1);
        int headerEnd = raw.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (headerEnd < 0) {
            headerEnd = raw.indexOf("\n\n");
            sepLen = 2;
        }
        String headerText = raw;
        String bodyText = "";
        if (headerEnd >= 0) {
            headerText = raw.substring(0, headerEnd);
            bodyText = raw.substring(headerEnd + sepLen);
        }
        if (headerText.trim().isEmpty()) {
            return;
        }
        msg.setResponseHeader(headerText);
        msg.setResponseBody(bodyText);
    }
}
