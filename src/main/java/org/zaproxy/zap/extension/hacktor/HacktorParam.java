package org.zaproxy.zap.extension.hacktor;

import java.util.LinkedHashMap;
import java.util.Map;
import org.parosproxy.paros.common.AbstractParam;

/**
 * All persistent Hacktor configuration, registered with ZAP via
 * {@code ExtensionHook.addOptionsParamSet(...)}.
 *
 * <p>Previously the addon read and wrote {@code Model.getSingleton().getOptionsParam()
 * .getConfig()} directly under loose {@code hacktor.*} keys. That worked, but it
 * bypassed ZAP's own configuration machinery: the options never appeared in the
 * ZAP Options UI, and they were not part of the config set ZAP validates, imports
 * or exports. Owning an {@link AbstractParam} fixes both, and lets ZAP drive
 * parsing at startup via {@link #parse()}.
 *
 * <p>Two on-disk details are handled here:
 * <ul>
 *   <li><b>Trailing newlines.</b> The old code packed every general setting into a
 *       single newline-delimited {@code hacktor.settings} string. XML
 *       serialisation strips one trailing newline on write, so the value in memory
 *       and the value on disk were never byte-identical. Each setting is now its
 *       own key, so there is no delimiter to lose.</li>
 *   <li><b>Upgrade.</b> A pre-existing {@code hacktor.settings} blob is expanded
 *       into the individual keys on first load and rewritten in the new form, so
 *       upgrading the addon does not silently reset everyone's configuration.</li>
 * </ul>
 */
public class HacktorParam extends AbstractParam {

    /** Base key for every option. ZAP's config namespace, not a shared one. */
    private static final String P = "hacktor.";

    /** Legacy single-blob key, read once and then superseded. */
    private static final String LEGACY_SETTINGS_KEY = P + "settings";

    // ── General run ──
    private boolean followRedirects = true;
    private boolean suppressErrors = true;
    private boolean stopOnCandidate = false;
    private boolean retryOnError = false;
    private boolean useRawWire = true;
    private boolean backoff = false;
    private boolean fuzzMode = false;
    private boolean fuzzUrl = true;
    private int urlMode = 0;
    private boolean fuzzHeader = true;
    private boolean fuzzBody = false;
    private boolean classicTier = true;
    private boolean rareTier = true;
    private boolean novelTier = true;
    private boolean oauthClassic = true;
    private boolean oauthRare = true;
    private boolean oauthNovel = true;
    private boolean showCustomOnly = false;
    private boolean exactWire = false;
    private boolean candidatesOnly = false;
    private boolean errorsOnly = false;
    private int rateLimit = 0;
    private int threads = 1;
    private int timeout = 5;
    private int maxProbes = 0;
    private int maxResults = 10000;
    private int logCap = 500;
    private int filterCol = 0;
    private int vulnType = 0;
    private int position = 0;
    private int bodyMode = 0;
    private String wordlist = "";

    // ── Blobs (line-delimited sets, stored verbatim) ──
    private String oobUrl = "";
    private String famOn = "";
    private String famOff = "";
    private String rowsOn = "";
    private String rowsOff = "";
    private String headers = "";
    private String fixedheaders = "";

    /**
     * Bumped whenever the on-disk shape changes, so {@link #parse()} knows whether the
     * legacy blob has already been expanded.
     */
    private static final int CURRENT_VERSION = 1;
    private static final String VERSION_KEY = P + "version";

    /** Set when a legacy blob was found and rewritten, so ZAP saves the upgrade. */
    private boolean upgraded;

    @Override
    protected void parse() {
        if (getConfig() == null) {
            return;
        }
        upgraded = expandLegacySettings();

        followRedirects = getBoolean(P + "followRedirects", true);
        suppressErrors = getBoolean(P + "suppressErrors", true);
        stopOnCandidate = getBoolean(P + "stopOnCandidate", false);
        retryOnError = getBoolean(P + "retryOnError", false);
        useRawWire = getBoolean(P + "useRawWire", true);
        backoff = getBoolean(P + "backoff", false);
        fuzzMode = getBoolean(P + "fuzzMode", false);
        fuzzUrl = getBoolean(P + "fuzzUrl", true);
        urlMode = getInt(P + "urlMode", 0);
        fuzzHeader = getBoolean(P + "fuzzHeader", true);
        fuzzBody = getBoolean(P + "fuzzBody", false);
        classicTier = getBoolean(P + "classicTier", true);
        rareTier = getBoolean(P + "rareTier", true);
        novelTier = getBoolean(P + "novelTier", true);
        oauthClassic = getBoolean(P + "oauthClassic", true);
        oauthRare = getBoolean(P + "oauthRare", true);
        oauthNovel = getBoolean(P + "oauthNovel", true);
        showCustomOnly = getBoolean(P + "showCustomOnly", false);
        exactWire = getBoolean(P + "exactWire", false);
        candidatesOnly = getBoolean(P + "candidatesOnly", false);
        errorsOnly = getBoolean(P + "errorsOnly", false);
        rateLimit = getInt(P + "rateLimit", 0);
        threads = getInt(P + "threads", 1);
        timeout = getInt(P + "timeout", 5);
        maxProbes = getInt(P + "maxProbes", 0);
        maxResults = getInt(P + "maxResults", 10000);
        logCap = getInt(P + "logCap", 500);
        filterCol = getInt(P + "filterCol", 0);
        vulnType = getInt(P + "vulnType", 0);
        position = getInt(P + "position", 0);
        bodyMode = getInt(P + "bodyMode", 0);
        wordlist = getString(P + "wordlist", "");

        oobUrl = getString(P + "oobUrl", "");
        famOn = getString(P + "famOn", "");
        famOff = getString(P + "famOff", "");
        rowsOn = getString(P + "rowsOn", "");
        rowsOff = getString(P + "rowsOff", "");
        headers = getString(P + "headers", "");
        fixedheaders = getString(P + "fixedheaders", "");
    }

    /**
     * Expands a legacy {@code hacktor.settings} blob into individual keys, once.
     *
     * <p>Returns true if a rewrite happened, so the caller can persist it. Individual
     * keys always win: if they are already present the blob is ignored and dropped,
     * because that means the new format is in use and the blob is stale.
     */
    private boolean expandLegacySettings() {
        if (getConfig().containsKey(VERSION_KEY)) {
            // Already upgraded. Drop a leftover blob so it cannot mislead anyone reading
            // the config by hand.
            if (getConfig().containsKey(LEGACY_SETTINGS_KEY)) {
                getConfig().clearProperty(LEGACY_SETTINGS_KEY);
                return true;
            }
            return false;
        }
        String raw = getString(LEGACY_SETTINGS_KEY, null);
        getConfig().clearProperty(LEGACY_SETTINGS_KEY);
        if (raw == null || raw.isEmpty()) {
            getConfig().setProperty(VERSION_KEY, CURRENT_VERSION);
            return true;
        }
        Map<String, String> m = new LinkedHashMap<>();
        for (String line : raw.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                m.put(line.substring(0, eq).trim(), line.substring(eq + 1));
            }
        }
        // Only set keys that are still absent, so a partial upgrade never downgrades.
        for (Map.Entry<String, String> e : m.entrySet()) {
            String key = P + e.getKey();
            if (!getConfig().containsKey(key)) {
                getConfig().setProperty(key, unescape(e.getValue()));
            }
        }
        getConfig().setProperty(VERSION_KEY, CURRENT_VERSION);
        return true;
    }

    private static String unescape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case '\\': sb.append('\\'); break;
                    default: sb.append('\\').append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Binds this param set to ZAP's config, parsing it, if it is not bound yet.
     *
     * <p>{@link AbstractParam} only has a config once something has called
     * {@code load(...)} on it. ZAP does that for registered param sets during
     * startup, but the work panel is constructed from
     * {@code ExtensionAdaptor.hook(...)}, and the ordering between that hook and
     * the config load is not something an extension should depend on. Binding
     * lazily here means the panel works whichever order ZAP uses, instead of
     * silently discarding every setting change.
     *
     * <p>Call this once when a view binds to the param, before mutating fields:
     * binding re-reads the config, so any pending field change would be discarded.
     */
    public void ensureConfig() {
        if (getConfig() != null) {
            return;
        }
        try {
            org.apache.commons.configuration.FileConfiguration cfg =
                org.parosproxy.paros.model.Model.getSingleton()
                    .getOptionsParam().getConfig();
            if (cfg != null) {
                load(cfg);
            }
        } catch (Exception ignored) {
            // No usable config: save() will no-op rather than throw.
        }
    }

    /**
     * Writes every option to ZAP's config and flushes to disk.
     *
     * <p>The flush is deliberate: the work panel persists on every control change
     * rather than waiting for a shutdown, so a crash or a kill cannot lose settings.
     */
    public void save() {
        if (getConfig() == null) {
            return;
        }
        getConfig().setProperty(VERSION_KEY, CURRENT_VERSION);

        getConfig().setProperty(P + "followRedirects", followRedirects);
        getConfig().setProperty(P + "suppressErrors", suppressErrors);
        getConfig().setProperty(P + "stopOnCandidate", stopOnCandidate);
        getConfig().setProperty(P + "retryOnError", retryOnError);
        getConfig().setProperty(P + "useRawWire", useRawWire);
        getConfig().setProperty(P + "backoff", backoff);
        getConfig().setProperty(P + "fuzzMode", fuzzMode);
        getConfig().setProperty(P + "fuzzUrl", fuzzUrl);
        getConfig().setProperty(P + "urlMode", urlMode);
        getConfig().setProperty(P + "fuzzHeader", fuzzHeader);
        getConfig().setProperty(P + "fuzzBody", fuzzBody);
        getConfig().setProperty(P + "classicTier", classicTier);
        getConfig().setProperty(P + "rareTier", rareTier);
        getConfig().setProperty(P + "novelTier", novelTier);
        getConfig().setProperty(P + "oauthClassic", oauthClassic);
        getConfig().setProperty(P + "oauthRare", oauthRare);
        getConfig().setProperty(P + "oauthNovel", oauthNovel);
        getConfig().setProperty(P + "showCustomOnly", showCustomOnly);
        getConfig().setProperty(P + "exactWire", exactWire);
        getConfig().setProperty(P + "candidatesOnly", candidatesOnly);
        getConfig().setProperty(P + "errorsOnly", errorsOnly);
        getConfig().setProperty(P + "rateLimit", rateLimit);
        getConfig().setProperty(P + "threads", threads);
        getConfig().setProperty(P + "timeout", timeout);
        getConfig().setProperty(P + "maxProbes", maxProbes);
        getConfig().setProperty(P + "maxResults", maxResults);
        getConfig().setProperty(P + "logCap", logCap);
        getConfig().setProperty(P + "filterCol", filterCol);
        getConfig().setProperty(P + "vulnType", vulnType);
        getConfig().setProperty(P + "position", position);
        getConfig().setProperty(P + "wordlist", wordlist);

        getConfig().setProperty(P + "oobUrl", oobUrl);
        getConfig().setProperty(P + "famOn", famOn);
        getConfig().setProperty(P + "famOff", famOff);
        getConfig().setProperty(P + "rowsOn", rowsOn);
        getConfig().setProperty(P + "rowsOff", rowsOff);
        getConfig().setProperty(P + "headers", headers);
        getConfig().setProperty(P + "fixedheaders", fixedheaders);

        try {
            getConfig().save();
        } catch (Exception ignored) {
            // A read-only or unwritable config must not break the run.
        }
    }

    /** True if {@link #parse()} expanded a legacy blob and it still needs saving. */
    public boolean isUpgraded() {
        return upgraded;
    }

    // ── Accessors ──

    public boolean isFollowRedirects() { return followRedirects; }
    public void setFollowRedirects(boolean v) { followRedirects = v; }
    public boolean isSuppressErrors() { return suppressErrors; }
    public void setSuppressErrors(boolean v) { suppressErrors = v; }
    public boolean isStopOnCandidate() { return stopOnCandidate; }
    public void setStopOnCandidate(boolean v) { stopOnCandidate = v; }
    public boolean isRetryOnError() { return retryOnError; }
    public void setRetryOnError(boolean v) { retryOnError = v; }
    public boolean isUseRawWire() { return useRawWire; }
    public void setUseRawWire(boolean v) { useRawWire = v; }
    public boolean isBackoff() { return backoff; }
    public void setBackoff(boolean v) { backoff = v; }
    public boolean isFuzzMode() { return fuzzMode; }
    public void setFuzzMode(boolean v) { fuzzMode = v; }
    public boolean isFuzzUrl() { return fuzzUrl; }
    public void setFuzzUrl(boolean v) { fuzzUrl = v; }
    public int getUrlMode() { return urlMode; }
    public void setUrlMode(int v) { urlMode = v; }
    public boolean isFuzzHeader() { return fuzzHeader; }
    public void setFuzzHeader(boolean v) { fuzzHeader = v; }
    public boolean isFuzzBody() { return fuzzBody; }
    public void setFuzzBody(boolean v) { fuzzBody = v; }
    public boolean isClassicTier() { return classicTier; }
    public void setClassicTier(boolean v) { classicTier = v; }
    public boolean isRareTier() { return rareTier; }
    public void setRareTier(boolean v) { rareTier = v; }
    public boolean isNovelTier() { return novelTier; }
    public void setNovelTier(boolean v) { novelTier = v; }
    public boolean isOauthClassic() { return oauthClassic; }
    public void setOauthClassic(boolean v) { oauthClassic = v; }
    public boolean isOauthRare() { return oauthRare; }
    public void setOauthRare(boolean v) { oauthRare = v; }
    public boolean isOauthNovel() { return oauthNovel; }
    public void setOauthNovel(boolean v) { oauthNovel = v; }
    public boolean isShowCustomOnly() { return showCustomOnly; }
    public void setShowCustomOnly(boolean v) { showCustomOnly = v; }
    public boolean isExactWire() { return exactWire; }
    public void setExactWire(boolean v) { exactWire = v; }
    public boolean isCandidatesOnly() { return candidatesOnly; }
    public void setCandidatesOnly(boolean v) { candidatesOnly = v; }
    public boolean isErrorsOnly() { return errorsOnly; }
    public void setErrorsOnly(boolean v) { errorsOnly = v; }
    public int getRateLimit() { return rateLimit; }
    public void setRateLimit(int v) { rateLimit = v; }
    public int getThreads() { return threads; }
    public void setThreads(int v) { threads = v; }
    public int getTimeout() { return timeout; }
    public void setTimeout(int v) { timeout = v; }
    public int getMaxProbes() { return maxProbes; }
    public void setMaxProbes(int v) { maxProbes = v; }
    public int getMaxResults() { return maxResults; }
    public void setMaxResults(int v) { maxResults = v; }
    public int getLogCap() { return logCap; }
    public void setLogCap(int v) { logCap = v; }
    public int getFilterCol() { return filterCol; }
    public void setFilterCol(int v) { filterCol = v; }
    public int getVulnType() { return vulnType; }
    public void setVulnType(int v) { vulnType = v; }
    public int getPosition() { return position; }
    public void setPosition(int v) { position = v; }
    public int getBodyMode() { return bodyMode; }
    public void setBodyMode(int v) { bodyMode = v; }
    public String getWordlist() { return wordlist; }
    public void setWordlist(String v) { wordlist = v == null ? "" : v; }

    public String getOobUrl() { return oobUrl; }
    public void setOobUrl(String v) { oobUrl = v == null ? "" : v; }
    public String getFamOn() { return famOn; }
    public void setFamOn(String v) { famOn = v == null ? "" : v; }
    public String getFamOff() { return famOff; }
    public void setFamOff(String v) { famOff = v == null ? "" : v; }
    public String getRowsOn() { return rowsOn; }
    public void setRowsOn(String v) { rowsOn = v == null ? "" : v; }
    public String getRowsOff() { return rowsOff; }
    public void setRowsOff(String v) { rowsOff = v == null ? "" : v; }
    public String getHeaders() { return headers; }
    public void setHeaders(String v) { headers = v == null ? "" : v; }
    public String getFixedHeaders() { return fixedheaders; }
    public void setFixedHeaders(String v) { fixedheaders = v == null ? "" : v; }
}
