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

    private final String family;
    private final String label;
    private final String description;
    private boolean enabled = true;
    private boolean needsRawWire = false;
    private final ApplyFunction apply;
    private final boolean custom;
    private VulnCatalog.Tier tier = VulnCatalog.Tier.CLASSIC;

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

    /** Returns a functional duplicate of this technique. Custom techniques keep their
     *  custom attributes; built-ins keep their compiled apply function, so the copy is
     *  fully runnable and preserves this technique's tier and raw-wire behaviour. */
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
        return c;
    }

    @Override
    public String toString() { return family + ": " + label; }
}
