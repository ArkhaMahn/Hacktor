package org.zaproxy.zap.extension.hacktor.technique;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Protocol / scheme tampering at the request-target and upgrade-mechanism level.
 *
 * <p>Covers the request-line scheme swaps (absolute-form with ws:/wss:/ftp:/file:/
 * gopher:/dict:/ldap:/data:/telnet: targets, which naive forwarders / legacy vhosts
 * route on), and the HTTP upgrade handshakes used to jump protocols in either
 * direction: h2c (HTTP/1.1 cleartext upgrade to HTTP/2), h2 (TLS Upgrade header),
 * websocket (RFC 6455), TLS (RFC 2817 Upgrade: TLS/1.0) and SPDY. A server that
 * answers a downgraded/upgraded request differently is the inference signal.
 */
public class SchemeTamperingTechniqueBuilder extends AbstractTechniqueBuilder {
    @Override public String getFamily() { return "Scheme Tampering"; }
    @Override public int getOrder() { return 25; }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      TechniqueBuilder.PathContext ctx) {
        String base = ctx.baseClean;
        if (base == null || base.isEmpty()) base = "/";

        // Absolute-form request-target with alternate schemes. Some stacks route /
        // forward on the scheme authority, so the target host sees a different
        // protocol than the socket it is actually speaking.
        String[] schemes = {
            "ws://localhost", "wss://localhost", "ftp://localhost",
            "ftps://localhost", "file:///etc/passwd", "gopher://localhost:70/",
            "dict://localhost:11211/", "ldap://localhost:389/",
            "data:text/plain;base64,SGVsbG8=", "telnet://localhost:23/",
            "ssh://localhost/", "git://localhost/",
        };
        for (String sc : schemes) {
            final String target = sc + base;
            markRawAdd(techs, new Technique("Scheme Tampering", "Scheme:" + sc.split(":")[0].replace("/", "SL"),
                "Absolute-form request-target using scheme '" + sc.split(":")[0]
                    + "' against the current socket: " + target,
                baseMsg -> { HttpMessage c = cloneMsg(baseMsg); replacePath(c, target); return c; }));
        }

        // HTTP/2 cleartext upgrade (RFC 7540 3.2): a CHUNKED-safe handshake that
        // converts an HTTP/1.1 connection into HTTP/2 on plain TCP.
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:h2c",
            "HTTP/2 cleartext upgrade: Connection: Upgrade, HTTP2-Settings + Upgrade: h2c",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Connection", "Upgrade, HTTP2-Settings");
                c.getRequestHeader().setHeader("Upgrade", "h2c");
                c.getRequestHeader().setHeader("HTTP2-Settings", "AAMAAABkAAQAAP__");
                return c; }));

        // h2c advert only (without Settings) and bare h2 (TLS) Upgrade probe.
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:h2cBare",
            "Bare HTTP/2 upgrade advert: Upgrade: h2c",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Upgrade", "h2c");
                return c; }));
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:h2",
            "TLS HTTP/2 Upgrade advert: Upgrade: h2",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Upgrade", "h2");
                c.getRequestHeader().setHeader("Connection", "Upgrade");
                return c; }));

        // RFC 6455 websocket upgrade handshake over the HTTP request line.
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:websocket",
            "WebSocket upgrade handshake (RFC 6455): Upgrade: websocket",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Connection", "Upgrade, keep-alive");
                c.getRequestHeader().setHeader("Upgrade", "websocket");
                c.getRequestHeader().setHeader("Sec-WebSocket-Key", "x3JJHMbDL1EzLkh9GBhXDw==");
                c.getRequestHeader().setHeader("Sec-WebSocket-Version", "13");
                return c; }));

        // RFC 2817 Upgrade: TLS/1.0 (HTTP-over-TLS protocol switch) and SPDY.
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:TLS",
            "RFC 2817 TLS upgrade: Upgrade: TLS/1.0",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Connection", "Upgrade");
                c.getRequestHeader().setHeader("Upgrade", "TLS/1.0");
                return c; }));
        markRawAdd(techs, new Technique("Scheme Tampering", "Upgrade:SPDY",
            "SPDY upgrade advert: Upgrade: SPDY/3.1",
            baseMsg -> { HttpMessage c = cloneMsg(baseMsg);
                c.getRequestHeader().setHeader("Connection", "Upgrade");
                c.getRequestHeader().setHeader("Upgrade", "SPDY/3.1");
                return c; }));
    }
}