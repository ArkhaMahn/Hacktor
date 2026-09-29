package org.zaproxy.zap.extension.hacktor;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
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

    /** Bounded chunk size for the header scan. Deliberately much smaller than
     *  {@link #CHUNK} so a response whose body follows in the same TCP segment does
     *  not pull a whole body into the header buffer just to push it back. */
    private static final int HEAD_CHUNK = 1024;

    /** Pushback capacity: must exceed {@link #HEAD_CHUNK} so the unconsumed tail of
     *  a header read can always be handed back to the body readers. */
    private static final int PUSHBACK = HEAD_CHUNK + 1024;

    private RawHttpSender() {
    }

    /**
     * Pseudo-header carrying raw, pre-serialised header lines to emit at the top
     * of the header block. Needed for lines that ZAP's header model cannot hold
     * verbatim — a bare token with no colon, or a value containing raw CRLF. Stripped
     * before the rest of the headers are serialised, like the wire-path marker.
     */
    public static final String WIRE_HEADER_LINES = "X-Hacktor-WireHeaderLines";

    /**
     * Pseudo-header carrying a complete, pre-serialised request line. The header
     * model upper-cases the version field, so a status line replayed as a request
     * line would lose the case of its reason phrase. Stripped like the other markers.
     */
    public static final String WIRE_REQUEST_LINE = "X-Hacktor-WireRequestLine";

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

        // Some techniques need an exact request-target on the wire that a URI object
        // would re-encode or refuse: literal %XX padding (Padding), backslash/UNC
        // paths, and the non-origin-form targets produced by the character sweeps
        // (";admin", "\admin", a control byte before the leading slash). They mark the
        // path with a pseudo-header and we honour it here, then strip it before
        // serialising the rest of the headers.
        String wirePath = msg.getRequestHeader().getHeader("X-Hacktor-WirePath");

        String wireRequestLine = msg.getRequestHeader().getHeader(WIRE_REQUEST_LINE);

        String target;
        if (wireRequestLine != null && !wireRequestLine.isEmpty()) {
            // The line is fixed verbatim, so the request-target is not resolved at all.
            target = null;
        } else if (wirePath != null && !wirePath.isEmpty()) {
            target = wirePath;
        } else {
            target = buildRequestTarget(uri, secure);
            if (target == null) {
                return null;
            }
        }

        if (target == null) {
            sb.append(wireRequestLine).append("\r\n");
        } else {
            sb.append(method).append(' ').append(target).append(' ').append(version).append("\r\n");
        }

        // Some probes need a header line that is not a well-formed "name: value"
        // pair: a bare token line with no colon at all, or a line whose value
        // carries raw CRLF. ZAP's header model rewrites both ("x" + no colon
        // becomes "x : "), so those lines travel in a pseudo-header and are
        // prepended to the block verbatim.
        String wireLines = msg.getRequestHeader().getHeader(WIRE_HEADER_LINES);
        if (wireLines != null && !wireLines.isEmpty()) {
            // Stashed NUL-joined so the marker occupies exactly one header line and
            // the prefix strip below removes all of it; unpacked to CRLF here.
            StringBuilder packed = new StringBuilder(wireLines.length() + 8);
            for (int i = 0; i < wireLines.length(); i++) {
                char ch = wireLines.charAt(i);
                if (ch == '\u0000') {
                    packed.append("\r\n");
                } else {
                    packed.append(ch);
                }
            }
            wireLines = packed.toString();

        }

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
            block = stripHeaderLine(block, "X-Hacktor-WireRequestLine:");
            if (block == null) block = "";
            block = stripHeaderLine(block, "X-Hacktor-WireHeaderLines:");
            if (block == null) block = "";
            block = stripHeaderLine(block, "X-Hacktor-Timing:");
            if (block == null) block = "";
            if (wireLines != null && !wireLines.isEmpty()) {
                // Only join with a fresh CRLF when the caller did not already end the
                // last raw line with one. A technique that rebuilds a whole header
                // block line-by-line (header-order, colon-space suffix) ends its string
                // with CRLF, and appending another would emit a blank line that closes
                // the header block early.
                String sep = wireLines.endsWith("\r\n") ? "" : "\r\n";
                block = wireLines + sep + block;
            }
            sb.append(block);
        } else if (wireLines != null && !wireLines.isEmpty()) {
            sb.append(wireLines).append("\r\n");
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
        // A blocking stream's read() returns as soon as at least one byte is
        // available, so the header scan must never try to fill a whole buffer. Two
        // bugs come from doing that: it blocks for the full socket timeout on every
        // response, and it over-consumes body bytes that arrived in the same TCP
        // segment as the headers (which are then dropped, silently emptying the
        // body of every small response). Read in bounded chunks and push the
        // unconsumed tail back so the body readers still see it.
        PushbackInputStream pin = new PushbackInputStream(in, PUSHBACK);
        StringBuilder head = new StringBuilder(1024);
        byte[] buf = new byte[HEAD_CHUNK];
        boolean seenHeaderEnd = false;
        while (!seenHeaderEnd) {
            int n = pin.read(buf, 0, buf.length);
            if (n < 0) {
                // EOF with no bytes at all: nothing was sent.
                if (head.length() == 0) {
                    return null;
                }
                // Headers never terminated (truncated response): treat what we
                // have as the whole response so the read always terminates.
                break;
            }
            int consumed = 0;
            for (int i = 0; i < n; i++) {
                head.append((char) (buf[i] & 0xFF));
                consumed = i + 1;
                if (head.length() >= MAX_RESPONSE_HEADER) {
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
                        break;
                    }
                }
            }
            if (consumed < n) {
                pin.unread(buf, consumed, n - consumed);
            }
        }
        String headerText = head.toString();

        long len = getContentLength(headerText);
        boolean chunked = hasHeader(headerText, "Transfer-Encoding")
            && headerText.toLowerCase(Locale.ROOT).contains("chunked");

        StringBuilder body;
        if (chunked) {
            body = readChunked(pin);
        } else if (len >= 0) {
            body = readFixed(pin, len);
        } else {
            // No framing: read until EOF (legacy 1.0 style), capped.
            body = new StringBuilder();
            byte[] bodyBuf = new byte[CHUNK];
            int n;
            while (body.length() < MAX_RESPONSE_BODY
                && (n = pin.read(bodyBuf, 0,
                    (int) Math.min(bodyBuf.length, MAX_RESPONSE_BODY - body.length()))) > 0) {
                for (int i = 0; i < n; i++) {
                    body.append((char) (bodyBuf[i] & 0xFF));
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
            // Ask only for what is still owed, and take a single read: a short read
            // is normal and must not be mistaken for end-of-body.
            int want = (int) Math.min(remaining, buf.length);
            int n = in.read(buf, 0, want);
            if (n < 0) {
                break;
            }
            for (int i = 0; i < n; i++) {
                sb.append((char) (buf[i] & 0xFF));
            }
            remaining -= n;
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
                int want = (int) Math.min(toRead - have, buf.length);
                int n = in.read(buf, 0, want);
                if (n < 0) {
                    return sb;
                }
                for (int i = 0; i < n; i++) {
                    sb.append((char) (buf[i] & 0xFF));
                }
                have += n;
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
