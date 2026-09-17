package org.zaproxy.zap.extension.hacktor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Payload encoders mirroring the transforms offered by the Recode ZAP add-on
 * (https://github.com/arkhamahn/recode) — URL percent encoding at 1x/2x/3x,
 * Base64 (standard and URL-safe), ASCII hex, full HTML numeric entities and
 * illegal/overlong UTF-8 forms — used to generate WAF-evasion technique
 * variants of the vulnerability-catalog payloads.
 */
public final class PayloadEncoder {

    public enum Encoder {
        NONE("None", "None"),
        URL1("URL x1", "U1"),
        URL2("URL x2", "U2"),
        URL3("URL x3", "U3"),
        B64("Base64", "B64"),
        B64U("Base64 URL", "B64U"),
        HEX("ASCII Hex", "Hex"),
        HTML("HTML Entities", "Html"),
        OVERLONG("Overlong UTF-8", "Ov");

        private final String display;
        private final String code;

        Encoder(String display, String code) {
            this.display = display;
            this.code = code;
        }

        public String getDisplay() { return display; }
        public String code() { return code; }
    }

    private PayloadEncoder() {}

    /** Display names for UI dropdowns (Recode-style encoder list). */
    public static String[] displayNames() {
        Encoder[] all = Encoder.values();
        String[] names = new String[all.length];
        for (int i = 0; i < all.length; i++) names[i] = all[i].getDisplay();
        return names;
    }

    /** Maps a display name back to an {@link Encoder}; unknown/null → NONE. */
    public static Encoder fromDisplay(String display) {
        if (display == null) return Encoder.NONE;
        for (Encoder e : Encoder.values()) {
            if (e.getDisplay().equalsIgnoreCase(display)) return e;
        }
        return Encoder.NONE;
    }

    /** Applies the chosen encoder to a payload (NONE returns the input). */
    public static String encode(String payload, Encoder enc) {
        if (payload == null || enc == null || enc == Encoder.NONE) return payload;
        switch (enc) {
            case URL1:   return urlEncode(payload, 1);
            case URL2:   return urlEncode(payload, 2);
            case URL3:   return urlEncode(payload, 3);
            case B64:    return base64(payload);
            case B64U:   return base64Url(payload);
            case HEX:    return asciiHex(payload);
            case HTML:   return htmlEntities(payload);
            case OVERLONG: return overlong(payload);
            default:     return payload;
        }
    }

    /**
     * URL percent-encodes a payload 1..3 times.
     * Pass 1 encodes every byte outside the unreserved set; each further pass
     * re-encodes the '%' of the previous result, producing the layered
     * {@code %3C…} / {@code %253C…} / {@code %25253C…} WAF beat-the-decoder
     * ladder (Request-For-… decoders unwrap one layer, the app unwraps again).
     */
    public static String urlEncode(String payload, int passes) {
        if (payload == null) return null;
        String s = percentEncode(payload);
        for (int i = 1; i < passes; i++) {
            s = s.replace("%", "%25");
        }
        return s;
    }

    private static String percentEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
                    || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%');
                sb.append(HEX_UPPER[c >> 4]);
                sb.append(HEX_UPPER[c & 0x0F]);
            }
        }
        return sb.toString();
    }

    private static final char[] HEX_UPPER =
        {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    /** Standard Base64 of the UTF-8 bytes. */
    public static String base64(String payload) {
        return Base64.getEncoder()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }

    /** URL-safe Base64 without padding. */
    public static String base64Url(String payload) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }

    /** Lowercase ASCII hex of the UTF-8 bytes. */
    public static String asciiHex(String payload) {
        StringBuilder sb = new StringBuilder();
        for (byte b : payload.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            sb.append(HEX_LOWER[c >> 4]).append(HEX_LOWER[c & 0x0F]);
        }
        return sb.toString();
    }

    /** Full HTML numeric entities: every char becomes &#<decimal>; */
    public static String htmlEntities(String payload) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < payload.length(); i++) {
            sb.append("&#").append((int) payload.charAt(i)).append(';');
        }
        return sb.toString();
    }

    // Recode's "Illegal UTF-8" generator: metacharacters re-cast as non-shortest
    // byte sequences the WAF rejects as junk while lenient decoders re-fold to the
    // original character. Two-byte overlong form: %c0 + (0x80 | byte).
    private static final char[] HEX_LOWER =
        {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private static final String OVERLONG_TARGETS = "/.<>'\"=;#";
    private static final String[] OVERLONG_ENCODED = new String[256];

    static {
        for (int i = 0; i < OVERLONG_TARGETS.length(); i++) {
            int b = OVERLONG_TARGETS.charAt(i);
            OVERLONG_ENCODED[b] = "%c0%" + lowerHex2(0x80 | b);
        }
    }

    private static String lowerHex2(int v) {
        return new String(new char[]{HEX_LOWER[(v >> 4) & 0xF], HEX_LOWER[v & 0xF]});
    }

    /** Overlong-encodes the WAF metacharacters ({@code / . < > ' " = ; #}). */
    public static String overlong(String payload) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < payload.length(); i++) {
            char ch = payload.charAt(i);
            if (ch < 256 && OVERLONG_ENCODED[ch] != null) {
                sb.append(OVERLONG_ENCODED[ch]);
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }
}