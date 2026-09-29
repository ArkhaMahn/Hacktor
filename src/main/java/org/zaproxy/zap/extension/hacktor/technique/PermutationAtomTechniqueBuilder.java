package org.zaproxy.zap.extension.hacktor.technique;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.hacktor.Technique;
import org.zaproxy.zap.extension.hacktor.VulnCatalog;

/**
 * The discrete permutation atoms from PortSwigger's <em>http-terminator</em>
 * validator ({@code validator/src/main/java/burp/atoms/}) that are not already
 * covered by another ported family.
 *
 * <p>http-terminator composes techniques out of small, independently-testable
 * mutations ("atoms") and then runs a permutation pipeline over them. Most of the
 * atoms map onto a family ported earlier — {@code Http10Atom} onto Minimal Request,
 * {@code OptionsStarAtom} onto Request Line and {@code MethodVariationAtom} onto
 * Methods. The rest are here, including the four framing atoms
 * ({@code ChunkedEncoding}, {@code ChunkedEncodingNoCl}, {@code ClToTe} and
 * {@code RemoveContentLength}), which rewrite the <em>body</em> rather than only
 * the framing headers.
 *
 * <p>{@code PayloadVariationAtom} and {@code TechniqueMergeAtom} have no static
 * wire form to port: one picks a random non-default payload at scan time and the
 * other composes atoms together, so both are properties of the upstream driver
 * rather than of a request. Hacktor generates a fixed, reportable technique set
 * instead, and the payload atoms are covered by the Desync Polyglot family, which
 * enumerates the same 13 payloads deterministically.
 *
 * <p>Each remaining atom is a <em>single</em> observable mutation, so unlike the
 * smuggling corpora it is applied to the base request as-is rather than embedded
 * in a polyglot. Three of them (header reordering, the semicolon and
 * colon-space suffixes) exist purely to break a parser's or a WAF's assumptions
 * about header syntax and ordering rather than about request framing.
 */
public class PermutationAtomTechniqueBuilder extends DesyncTechniqueBuilder {

    @Override public String getFamily() { return "Permutation Atoms"; }
    @Override public int getOrder() { return 72; }

    /** Mixed family: path, header and framing atoms, stamped per technique. */
    @Override public Technique.Position getPosition() { return null; }

    private static final String FAMILY = "Permutation Atoms";

    /**
     * Headers the upstream atoms refuse to touch. {@code Host} and
     * {@code Content-Length} are excluded because corrupting them does not produce
     * an interesting differential — a wrong Host changes which server answers, and a
     * wrong Content-Length changes the framing, both of which other families already
     * cover deliberately.
     */
    private static boolean isMutable(String name) {
        return !("host".equalsIgnoreCase(name) || "content-length".equalsIgnoreCase(name));
    }

    @Override
    public void build(List<Technique> techs, BiConsumer<HttpMessage, String> setPath,
                      PathContext ctx) {
        final String baseClean = ctx.baseClean;

        // ── ExpectHeaderAtom ──────────────────────────────────────────────
        // A front end that forwards Expect: 100-continue will wait for an interim
        // response before forwarding the body; one that strips it forwards
        // immediately. The divergence is a classic smuggling pivot, and it also
        // changes whether the body is read at all.
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:Expect100",
            "Expect: 100-continue header - front ends that forward it wait for an "
                + "interim response before sending the body",
            base -> {
                HttpMessage c = cloneMsg(base);
                addWireHeaderLines(c, "Expect: 100-continue");
                return c;
            }));

        // ── MaxForwardsAtom ───────────────────────────────────────────────
        // RFC 7231 allows a proxy to reject a request with Max-Forwards: 0 as if it
        // were a 502. A guard in front of the origin that honours it can be turned
        // into a blind proxy for requests the guard would otherwise drop.
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:MaxForwards0",
            "Max-Forwards: 0 - a compliant proxy must reject with 502, so a differential "
                + "reveals a proxy in the path",
            base -> {
                HttpMessage c = cloneMsg(base);
                addWireHeaderLines(c, "Max-Forwards: 0");
                return c;
            }));

        // ── Http2Atom ─────────────────────────────────────────────────────
        // X-Http2: 1 (and the X-Forwarded-Proto: https twin already in Protocol
        // Downgrade) tell a front end to treat the request as HTTP/2 for the purposes
        // of pseudo-header parsing, while the request line stays HTTP/1.1.
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:XHttp2",
            "X-Http2: 1 - an HTTP/1.1 request line asking to be treated as HTTP/2, so "
                + ":authority / :path pseudo-headers are worth resolving",
            base -> {
                HttpMessage c = cloneMsg(base);
                addWireHeaderLines(c, "X-Http2: 1");
                return c;
            }));

        // ── PathVariationAtom ─────────────────────────────────────────────
        // The path is replaced wholesale, keeping the connection alive. These matter
        // because a guard and an origin frequently normalise well-known static paths
        // differently from application paths: /favicon.ico and /robots.txt are often
        // served by a different vhost or skipped by the WAF, and /static is a common
        // mount-point prefix. /con is a Windows reserved device name, which reaches
        // a Windows-backed origin as a device rather than a file.
        pathVariant(techs, "Atom:PathCon", "/con (Windows reserved device name, directory preserved)", ctx.lastSeg.isEmpty() ? "/" : baseClean + "/con");
        pathVariant(techs, "Atom:PathFavicon", "/favicon.ico", "/favicon.ico");
        pathVariant(techs, "Atom:PathRobots", "/robots.txt", "/robots.txt");
        pathVariant(techs, "Atom:PathStatic", "/static", "/static");

        // ── SemicolonSuffixAtom ───────────────────────────────────────────
        // Appending "; " to a header value is tolerated by RFC 7230 as trailing
        // whitespace, but parsers and WAF rule matchers disagree about whether the
        // value still ends where the suffix begins. Upstream updates each header in
        // place (withUpdatedHeader), so the suffix replaces the value rather than
        // adding a second copy of the header.
        at(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:SemicolonSuffix",
            "every mutable request header value suffixed with '; ' (Host and "
                + "Content-Length left alone)",
            base -> {
                HttpMessage c = cloneMsg(base);
                for (HttpHeaderField f : new ArrayList<>(c.getRequestHeader().getHeaders())) {
                    if (!isMutable(f.getName())) continue;
                    addHeader(c, f.getName(), f.getValue() + "; ");
                }
                return c;
            }));

        // ── HeaderNameSpaceSuffixAtom ─────────────────────────────────────
        // A space before the colon is illegal (RFC 7230 §3.2.4) but accepted by
        // several stacks. A normaliser that rejects the line and a stack that reads
        // the header as valid give two different views of the request.
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:HeaderNameSpaceSuffix",
            "every mutable request header name given a space before its colon "
                + "('X-Foo : v'), which RFC 7230 forbids but several stacks accept",
            base -> {
                HttpMessage c = cloneMsg(base);
                // Written as raw lines: ZAP's header model always emits "name: value"
                // with no space before the colon, so this mutation cannot be expressed
                // through setHeader at all.
                StringBuilder lines = new StringBuilder();
                for (HttpHeaderField f : new ArrayList<>(c.getRequestHeader().getHeaders())) {
                    if (!isMutable(f.getName())) continue;
                    lines.append(f.getName()).append(" : ").append(f.getValue()).append("\r\n");
                    removeHeader(c, f.getName());
                }
                addWireHeaderLines(c, lines.toString());
                return c;
            }));

        // ── HeaderShuffleAtom ─────────────────────────────────────────────
        // Upstream shuffles with a seeded RNG and re-runs; here the same idea is
        // expressed deterministically, because a single random permutation cannot be
        // reported or reproduced. Reversing the order covers the case that matters
        // most (a WAF rule matching headers positionally), and hoisting the first
        // header to the end covers the "first header wins" parsing bug.
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:HeaderOrderReverse",
            "request headers emitted in reverse order - a WAF rule or parser that "
                + "matches positionally sees a different request",
            base -> reverseHeaderOrder(base)));
        atRaw(techs, Technique.Position.HEADER, new Technique(FAMILY, "Atom:HeaderOrderRotate",
            "request headers rotated by one - moves every header across the "
                + "'first header' boundary a parser may stop at",
            base -> rotateHeaderOrder(base)));

        // ── ChunkedEncodingAtom / ChunkedEncodingNoClAtom / ClToTeAtom ─────
        // The four framing atoms upstream are the classic request-smuggling
        // primitives, and none of them is produced by the Request Smuggling family:
        // that family only ever sets the framing *headers*, leaving the body in
        // whatever form the base had. These actually rewrite the body, which is the
        // point -- a "Transfer-Encoding: chunked" header in front of an unchunked
        // body and a chunked body are different probes.
        //
        // ChunkedEncoding keeps the base Content-Length alongside the chunked body
        // (the TE.CL desync); ChunkedEncodingNoCl drops it. ClToTe swaps one for
        // the other without touching the body (CL.TE), and RemoveContentLength
        // leaves the body with no framing header at all (EOF framing).
        atRaw(techs, Technique.Position.REQUEST, new Technique(FAMILY, "Atom:ChunkedEncoding",
            "body chunk-encoded while the base Content-Length survives, so a front end "
                + "honouring TE and one honouring CL disagree on where the body ends",
            base -> {
                HttpMessage c = cloneMsg(base);
                applyRaw(c, null,
                    new String[][]{{"Transfer-Encoding", "chunked"}},
                    chunkEncode(bodyText(base)), Framing.AS_DECLARED);
                return c;
            }));
        atRaw(techs, Technique.Position.REQUEST, new Technique(FAMILY, "Atom:ChunkedEncodingNoCL",
            "body chunk-encoded with Content-Length removed, so only a server that "
                + "honours Transfer-Encoding can find the end of the request",
            base -> {
                HttpMessage c = cloneMsg(base);
                applyRaw(c, null,
                    new String[][]{{"Content-Length", null}, {"Transfer-Encoding", "chunked"}},
                    chunkEncode(bodyText(base)), Framing.AS_DECLARED);
                return c;
            }));
        atRaw(techs, Technique.Position.REQUEST, new Technique(FAMILY, "Atom:ClToTE",
            "Content-Length swapped for Transfer-Encoding with the body left "
                + "unchunked - the body is read as a chunk header by a TE server and "
                + "as raw bytes by a CL server",
            base -> {
                HttpMessage c = cloneMsg(base);
                applyRaw(c, null,
                    new String[][]{{"Content-Length", null}, {"Transfer-Encoding", "chunked"}},
                    bodyText(base), Framing.AS_DECLARED);
                return c;
            }));
        atRaw(techs, Technique.Position.REQUEST, new Technique(FAMILY, "Atom:RemoveContentLength",
            "Content-Length removed with no Transfer-Encoding in its place - the "
                + "request is framed by connection close, so a keep-alive front end "
                + "and the origin can disagree about its length",
            base -> {
                HttpMessage c = cloneMsg(base);
                applyRaw(c, null, new String[][]{{"Content-Length", null}},
                    bodyText(base), Framing.AS_DECLARED);
                return c;
            }));

        for (Technique t : techs) {
            if (FAMILY.equals(t.getFamily()) && t.getTier() == null) {
                t.setTier(VulnCatalog.Tier.RARE);
            }
        }
    }

    /** The base request body, as raw text. */
    private static String bodyText(HttpMessage base) {
        try {
            String s = base.getRequestBody().toString();
            return s == null ? "" : s;
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Chunk-encodes {@code body} exactly as upstream's {@code ChunkedEncodingAtom}
     * does: an empty body becomes a bare terminator, anything else gets a
     * single-chunk framing with no chunk extensions.
     */
    private static String chunkEncode(String body) {
        if (body == null || body.isEmpty()) return "0\r\n\r\n";
        return Integer.toHexString(body.length()) + "\r\n" + body + "\r\n0\r\n\r\n";
    }

    /** Replaces the request-target with a fixed path, keeping the base query. */
    private static void pathVariant(List<Technique> techs, String label, String desc,
                                    String path) {
        atRaw(techs, Technique.Position.URL, new Technique(FAMILY, label, desc,
            base -> {
                HttpMessage c = cloneMsg(base);
                setLiteralPath(c, path);
                return c;
            }));
    }

    /** Emits the request headers back-to-front, verbatim. */
    private static HttpMessage reverseHeaderOrder(HttpMessage base) {
        HttpMessage c = cloneMsg(base);
        StringBuilder lines = new StringBuilder();
        for (HttpHeaderField f : new ArrayList<>(c.getRequestHeader().getHeaders())) {
            if (f.getName().startsWith("X-Hacktor-")) continue;
            lines.append(f.getName()).append(": ").append(f.getValue()).append("\r\n");
        }
        for (HttpHeaderField f : new ArrayList<>(c.getRequestHeader().getHeaders())) {
            removeHeader(c, f.getName());
        }
        addWireHeaderLines(c, lines.toString());
        return c;
    }

    /** Emits the request headers rotated one position, verbatim. */
    private static HttpMessage rotateHeaderOrder(HttpMessage base) {
        HttpMessage c = cloneMsg(base);
        List<HttpHeaderField> fields = new ArrayList<>(c.getRequestHeader().getHeaders());
        List<HttpHeaderField> rotated = new ArrayList<>();
        for (int i = 1; i < fields.size(); i++) {
            if (!fields.get(i).getName().startsWith("X-Hacktor-")) rotated.add(fields.get(i));
        }
        if (!fields.isEmpty() && !fields.get(0).getName().startsWith("X-Hacktor-")) {
            rotated.add(fields.get(0));
        }
        StringBuilder lines = new StringBuilder();
        for (HttpHeaderField f : rotated) {
            lines.append(f.getName()).append(": ").append(f.getValue()).append("\r\n");
        }
        for (HttpHeaderField f : fields) {
            removeHeader(c, f.getName());
        }
        addWireHeaderLines(c, lines.toString());
        return c;
    }
}
