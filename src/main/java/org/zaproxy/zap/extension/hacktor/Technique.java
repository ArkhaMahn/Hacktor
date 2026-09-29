package org.zaproxy.zap.extension.hacktor;

import org.parosproxy.paros.network.HttpMessage;

/**
 * A single bypass probe.
 *
 * Built-in techniques carry an {@link ApplyFunction}.
 * Custom techniques carry path/header data and are applied by the engine.
 */
public final class Technique {

    public enum Verdict {
        CANDIDATE,
        SUPPRESSED,
        NO_CHANGE
    }

    /**
     * The request surface a technique targets.
     *
     * <p>This is a property of <em>where the probe lives</em>, not of how it is
     * applied, so it stays constant across tiers and encodings: the same SQLi
     * payload is a {@link #URL} technique in a path segment and a {@link #HEADER}
     * technique appended to {@code X-Forwarded-For}, and both are the same
     * injection class.
     *
     * <p>{@link #REQUEST} is the bucket for techniques that do not drop a payload
     * anywhere in particular but restructure the message as a whole: the method,
     * the request line, the HTTP version, message framing and the whole-request
     * smuggling corpora. Those probes are not "header" or "body" work even when
     * they do touch a header, because what is being tested is the request
     * structure rather than a value inside it. They are kept as a separate bucket
     * so that filtering to, say, header probes does not silently hide the entire
     * smuggling catalogue.
     */
    public enum Position {
        /** The request-target: path segments, root path, root query, query values. */
        URL("URL"),
        /** A request header: its value, name, casing, duplication or ordering. */
        HEADER("Header"),
        /** The message body, including parsed body parameters. */
        BODY("Body"),
        /** Request line, method, version, framing or a whole-request replay. */
        REQUEST("Request");

        private final String display;

        Position(String display) { this.display = display; }

        public String getDisplay() { return display; }

        @Override public String toString() { return display; }

        /** Parses a display name or enum name, case-insensitively; null if unknown. */
        public static Position fromString(String s) {
            if (s == null) return null;
            String t = s.trim();
            for (Position p : values()) {
                if (p.display.equalsIgnoreCase(t) || p.name().equalsIgnoreCase(t)) return p;
            }
            return null;
        }
    }

    private final String family;
    private final String label;
    private final String description;
    private boolean enabled = true;
    private boolean needsRawWire = false;
    private final ApplyFunction apply;
    private final boolean custom;
    private VulnCatalog.Tier tier = VulnCatalog.Tier.CLASSIC;
    /**
     * Request surface this technique targets. Null until stamped by the engine
     * (built-ins) or derived from the custom fields (custom techniques); the
     * filter treats null as {@link Position#REQUEST}.
     */
    private Position position;

    /** Custom technique: replacement path (null = header-only). */
    private String customPath;
    /** Custom technique: header name (null = path-only). */
    private String customHeaderName;
    /** Custom technique: header value (null = path-only). */
    private String customHeaderValue;
    /** Custom placement-probe technique: placement kind (null = not a placement probe). */
    private String customPlacement;
    /** Custom placement-probe technique: payload to drop. */
    private String customPayload;

    /**
     * Response statuses this technique treats as a parse error rather than a finding.
     * A response with one of these statuses is dropped from the result set instead of
     * being classified. Request-target fuzzing needs this: the
     * <em>URL Fuzzer 401/403 Bypass</em> tool states that a {@code 400} (or {@code 404})
     * answer to a fuzzed path means the front end simply refused to parse it, not that
     * the authorisation check was bypassed, and those are the two statuses it
     * explicitly ignores while scanning.
     */
    private int[] discardStatuses;
    /**
     * When true, a response with an empty body is dropped. The URL Fuzzer tool warns
     * that injecting a bare {@code \r\n} into the request line makes the server hang
     * until it gives up, and its scanner uses a non-empty body as the signal that a
     * response was real; an empty body means the connection died or the request was
     * swallowed, not that a guard was bypassed.
     */
    private boolean discardEmptyBody;

    public interface ApplyFunction {
        HttpMessage apply(HttpMessage base);
    }

    /** Standard built-in technique. */
    public Technique(String family, String label, String description, ApplyFunction apply) {
        this.family = family;
        this.label = label;
        this.description = description;
        this.apply = apply;
        this.custom = false;
    }

    /** Custom user-defined technique: path replacement (no header). */
    public Technique(String family, String label, String description, String customPath) {
        this.family = family;
        this.label = label;
        this.description = description;
        this.apply = null;
        this.custom = true;
        this.customPath = customPath;
        this.position = Position.URL;
    }

    /** Custom user-defined technique: header override (no path change). */
    public Technique(String family, String label, String description,
                     String headerName, String headerValue, boolean dummy) {
        this.family = family;
        this.label = label;
        this.description = description;
        this.apply = null;
        this.custom = true;
        this.customPath = null;
        this.customHeaderName = headerName;
        this.customHeaderValue = headerValue;
        this.position = Position.HEADER;
    }

    /** Custom user-defined placement probe: drop a payload at a placement site.
     *  Applied by the engine through the same placement engine used for the
     *  built-in vulnerability-class techniques. */
    public Technique(String family, String label, String description,
                     String placement, String payload) {
        this.family = family;
        this.label = label;
        this.description = description;
        this.apply = null;
        this.custom = true;
        this.customPlacement = placement;
        this.customPayload = payload;
        this.position = VulnCatalog.positionForPlacement(placement);
    }

    public VulnCatalog.Tier getTier() { return tier; }
    public void setTier(VulnCatalog.Tier tier) { if (tier != null) this.tier = tier; }

    public String getFamily() { return family; }
    public String getLabel() { return label; }
    public String getDescription() { return description; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isCustom() { return custom; }

    /**
     * The request surface this technique targets, never null: an unstamped
     * technique is reported as {@link Position#REQUEST}.
     */
    public Position getPosition() { return position == null ? Position.REQUEST : position; }
    /** True when no position has been stamped yet. */
    public boolean hasPosition() { return position != null; }
    public void setPosition(Position position) { this.position = position; }

    /**
     * True when this technique mutates the raw request line, framing, or headers in a
     * way that ZAP's normal {@code HttpSender} (commons-httpclient) would re-normalise
     * or strip on the wire (literal {@code #} fragments, malformed verbs / request lines,
     * HTTP/2 pseudo-headers, SMUGGLING framing). These are sent via {@link RawHttpSender}
     * so the exact bytes actually reach the server / proxy.
     */
    public boolean needsRawWire() { return needsRawWire; }
    public void setNeedsRawWire(boolean needsRawWire) { this.needsRawWire = needsRawWire; }

    public HttpMessage apply(HttpMessage base) {
        if (apply != null) return apply.apply(base);
        return null;
    }

    public String getCustomPath() { return customPath; }
    public void setCustomPath(String p) { this.customPath = p; }

    public String getCustomHeaderName() { return customHeaderName; }
    public void setCustomHeaderName(String h) { this.customHeaderName = h; }

    public String getCustomHeaderValue() { return customHeaderValue; }
    public void setCustomHeaderValue(String v) { this.customHeaderValue = v; }

    public String getCustomPlacement() { return customPlacement; }
    public void setCustomPlacement(String p) { this.customPlacement = p; }

    public String getCustomPayload() { return customPayload; }
    public void setCustomPayload(String p) { this.customPayload = p; }

    /** Configures the "parse error, not a finding" response rule. Pass null/empty
     *  statuses to keep the default behaviour (every status is classified). */
    public Technique setDiscardOn(int... statuses) {
        this.discardStatuses = (statuses == null || statuses.length == 0) ? null : statuses.clone();
        return this;
    }
    public int[] getDiscardStatuses() { return discardStatuses; }
    /** True when this response status is a non-finding for this technique. */
    public boolean discardsStatus(int status) {
        if (discardStatuses == null) return false;
        for (int s : discardStatuses) if (s == status) return true;
        return false;
    }

    /** Configures the empty-body drop rule used by the byte sweep (an empty answer to
     *  a fuzzed request-target means the server hung or dropped the connection). */
    public Technique setDiscardEmptyBody(boolean value) {
        this.discardEmptyBody = value;
        return this;
    }
    public boolean isDiscardEmptyBody() { return discardEmptyBody; }

    /** Returns a functional duplicate of this technique. Custom techniques keep their
     *  custom attributes; built-ins keep their compiled apply function, so the copy is
     *  fully runnable and preserves this technique's tier, raw-wire behaviour and
     *  parse-error response rule. */
    public Technique copy(String newLabel) {
        Technique c;
        if (custom) {
            if (customPlacement != null) {
                c = new Technique(family, newLabel, description, customPlacement, customPayload);
            } else if (customPath != null) {
                c = new Technique(family, newLabel, description, customPath);
            } else {
                c = new Technique(family, newLabel, description,
                    customHeaderName, customHeaderValue, false);
            }
        } else {
            c = new Technique(family, newLabel, description, apply);
        }
        c.setEnabled(enabled);
        c.setTier(tier);
        c.setNeedsRawWire(needsRawWire);
        c.position = position;
        c.discardStatuses = discardStatuses;
        c.discardEmptyBody = discardEmptyBody;
        return c;
    }

    @Override
    public String toString() { return family + ": " + label; }
}
