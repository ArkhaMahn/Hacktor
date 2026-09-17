package org.zaproxy.zap.extension.hacktor;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.view.HttpPanelManager;

/**
 * Main workbench panel for the Hacktor add-on.
 *
 * <p>Hosts four sub-tabs (Target / Techniques / Results / Log) and provides
 * fine-grained control over the probe run (rate limit, threads, per-probe timeout,
 * stop-on-candidate, retries, raw-wire forcing, max probe cap) and over what is
 * displayed (technique filtering, results filtering). The Results sub-tab shows the
 * selected probe's request and response through ZAP's core {@link HttpPanelRequest} /
 * {@link HttpPanelResponse} views (registered with {@link HttpPanelManager}).
 */
public class HacktorPanel extends AbstractPanel {

    private static final long serialVersionUID = 2L;
    private static final Insets INS = new Insets(4, 8, 4, 8);

    // ─── IntelliJ Dark theme colors ─────────────────────────────────────
    private static final Color BG        = new Color(0x3C, 0x3F, 0x41);
    private static final Color BG_DARK   = new Color(0x2B, 0x2B, 0x2B);
    private static final Color BG_PANEL  = new Color(0x32, 0x32, 0x32);
    private static final Color FG        = new Color(0xBB, 0xBB, 0xBB);
    private static final Color FG_DIM    = new Color(0x80, 0x80, 0x80);
    private static final Color FG_BRIGHT = new Color(0xAF, 0xAF, 0xAF);
    private static final Color ACCENT    = new Color(0x4A, 0x88, 0xC7);
    private static final Color ACCENT_LIGHT = new Color(135, 206, 235);
    private static final Font LABEL_H2   = new Font("SansSerif", Font.BOLD, 14);
    private static final Color SELECTION = new Color(0x21, 0x42, 0x83);
    private static final Color BORDER    = new Color(0x55, 0x55, 0x55);
    private static final Color BORDER_LT = new Color(0x66, 0x66, 0x66);
    private static final Color GREEN     = new Color(0x6A, 0x87, 0x59);
    private static final Color ORANGE    = new Color(0xCC, 0x78, 0x32);
    private static final Color YELLOW    = new Color(0xBB, 0xB5, 0x29);
    private static final Color RED       = new Color(0xCC, 0x66, 0x66);
    private static final Color CYAN      = new Color(0x68, 0x97, 0xBB);

    private final ExtensionHacktor extension;
    private final HacktorEngine engine = new HacktorEngine();

    // ─── ZAP core request/response viewers (Logger-style) ───────────────
    private final HttpPanelRequest requestViewer;
    private final HttpPanelResponse responseViewer;
    private final boolean[] panelsRegistered = {false};

    // ─── Target tab ─────────────────────────────────────────────────────
    private final JTextField urlField = new JTextField();
    private final JButton fromMessageButton = new JButton("From Selected");
    private final JButton fetchButton = new JButton("Fetch Baseline");
    private final JLabel baselineLabel = new JLabel("Baseline: not fetched");
    private final JTextField oobUrlField = new JTextField();
    private final JButton oobSaveButton = new JButton("Save OOB URL");
    private final JLabel oobStatusLabel = new JLabel("OOB callbacks: not configured");
    // ─── TamperOauth tab ────────────────────────────────────────────────
    private final JTextField oauthUrlField = new JTextField();
    private final JButton oauthDetectButton = new JButton("Detect");
    private final JButton oauthFromMessageButton = new JButton("From Selected");
    private final JLabel oauthEndpointLabel = new JLabel("Not detected");
    private final JLabel oauthFlowLabel = new JLabel("—");
    private final JLabel oauthParamsInfo = new JLabel("0 parameters");
    private final OauthParamTableModel oauthParamModel = new OauthParamTableModel();
    private final JTable oauthParamTable = new JTable(oauthParamModel);
    private final JButton oauthAddParamButton = new JButton("Add");
    private final JButton oauthRemoveParamButton = new JButton("Remove");
    private final JCheckBox oauthClassicBox = new JCheckBox("Classic", true);
    private final JCheckBox oauthRareBox = new JCheckBox("Rare", true);
    private final JCheckBox oauthNovelBox = new JCheckBox("Novel", true);
    private final TechniqueTableModel oauthTechniqueModel = new TechniqueTableModel();
    private final JTable oauthTechniqueTable = new JTable(oauthTechniqueModel);
    private final JButton oauthRunButton = new JButton("Run OAuth Run");
    private final JButton oauthStopButton = new JButton("Stop");
    private final JProgressBar oauthProgressBar = new JProgressBar(0, 100);
    private final JLabel oauthProgressLabel = new JLabel("Ready.");
    private final JLabel oauthCountLabel = new JLabel("0 techniques");
    private final JCheckBox followRedirectsBox = new JCheckBox("Follow Redirects", true);
    private final JCheckBox suppressErrorsBox = new JCheckBox("Suppress Custom Error Pages", true);
    private final JCheckBox stopOnCandidateBox = new JCheckBox("Stop on first Candidate", false);
    private final JCheckBox retryOnErrorBox = new JCheckBox("Retry on network error", false);
    private final JCheckBox useRawWireBox = new JCheckBox("Raw wire for ambiguous requests", true);
    private final JCheckBox backoffBox = new JCheckBox("Exp. backoff on 403/429 flag", false);
    private final JCheckBox fuzzModeBox = new JCheckBox("Fuzz Mode", false);
    private final JTextField fuzzWordlistField = new JTextField();
    private final JButton fuzzBrowseButton = new JButton("Browse\u2026");
    private final JCheckBox fuzzUrlBox = new JCheckBox("URL", true);
    private final JComboBox<String> urlModeCombo = new JComboBox<>(new String[]{
        "REPLACE", "APPEND", "PREPEND"});
    private final JCheckBox fuzzHeaderBox = new JCheckBox("Headers", true);
    private final JCheckBox fuzzBodyBox = new JCheckBox("Body", false);
    private final JLabel rateLimitLabel = new JLabel("Rate Limit:");
    private final JSpinner rateLimitSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 1));
    private final JLabel threadsLabel = new JLabel("Threads:");
    private final JSpinner threadsSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 16, 1));
    private final JLabel timeoutLabel = new JLabel("Timeout:");
    private final JSpinner timeoutSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 120, 1));
    private final JLabel maxProbesLabel = new JLabel("Max Probes:");
    private final JSpinner maxProbesSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 1));
    private final CustomHeaderTableModel customHeaderModel = new CustomHeaderTableModel();
    private final JTable customHeaderTable = new JTable(customHeaderModel);
    private final JButton addHeaderButton = new JButton("Add");
    private final JButton removeHeaderButton = new JButton("Remove");
    private final JButton clearHeaderButton = new JButton("Clear All");
    private final FixedHeaderTableModel fixedHeaderModel = new FixedHeaderTableModel();
    private final JTable fixedHeaderTable = new JTable(fixedHeaderModel);
    private final JButton addFixedHeaderButton = new JButton("Add");
    private final JButton removeFixedHeaderButton = new JButton("Remove");
    private final JComboBox<String> bodyModeCombo = new JComboBox<>(new String[]{
        "REPLACE", "APPEND", "PREPEND"});
    private final RSyntaxTextArea bodyTemplateEditor = new RSyntaxTextArea();
    private final JButton formatBodyButton = new JButton("Format");
    private final JButton addFuzzBodyButton = new JButton("Add FUZZ");
    private final JButton loadBodyButton = new JButton("Load from Base");
    private final JButton runButton = new JButton("Run");
    private final JButton stopButton = new JButton("Stop");
    private final JButton pauseButton = new JButton("Pause");
    private final JButton resumeButton = new JButton("Resume");
    private final JProgressBar progressBar = new JProgressBar(0, 100);
    private final JLabel progressLabel = new JLabel("Idle");
    private final JLabel statsLabel = new JLabel("Probes: 0 | Candidates: 0 | Elapsed: 0:00");
    private final javax.swing.Timer statsTimer =
        new javax.swing.Timer(500, e -> updateStatsLabel());

    // ─── Techniques tab ─────────────────────────────────────────────────
    private final JPanel familyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
    private final Map<String, JCheckBox> familyBoxes = new LinkedHashMap<>();
    private final JButton enableAllButton = new JButton("Enable All");
    private final JButton disableAllButton = new JButton("Disable All");
    private final JButton invertButton = new JButton("Invert");
    private final JButton addTechButton = new JButton("Add Custom");
    private final JButton editTechButton = new JButton("Edit");
    private final JButton removeTechButton = new JButton("Remove");
    private final JButton duplicateTechButton = new JButton("Duplicate");
    private final TechniqueTableModel techniqueModel = new TechniqueTableModel();
    private final JTable techniqueTable = new JTable(techniqueModel);
    private final JTextField filterField = new JTextField();
    private final JComboBox<String> filterColumnCombo = new JComboBox<>(new String[]{
        "All", "Label", "Family", "Description"});
    private final JLabel techniqueSummary = new JLabel("0 techniques");
    private final JCheckBox showCustomOnlyBox = new JCheckBox("Custom only", false);
    private final JComboBox<String> vulnTypeCombo = new JComboBox<>(new String[]{
        "All Types", "401/403 Bypass"});

    // ─── Results tab ────────────────────────────────────────────────────
    private final ResultsTableModel resultsModel = new ResultsTableModel();
    private final JTable resultsTable = new JTable(resultsModel);
    private final JButton exportButton = new JButton("Export CSV");
    private final JButton resendButton = new JButton("Resend");
    private final JButton copyUrlButton = new JButton("Copy URL");
    private final JButton clearResultsButton = new JButton("Clear");
    private final JButton copyCurlButton = new JButton("Copy as cURL");
    private final JLabel summaryLabel = new JLabel("Ready");
    private final JTextField resultsFilterField = new JTextField();
    private final JCheckBox candidatesOnlyBox = new JCheckBox("Candidates only", false);
    private final JCheckBox errorsOnlyBox = new JCheckBox("Errors only", false);

    // ─── Log tab ────────────────────────────────────────────────────────
    private final JTextArea logArea = new JTextArea();

    // ─── Advanced tab ───────────────────────────────────────────────────
    private final JCheckBox classicTierBox = new JCheckBox("Classic", true);
    private final JCheckBox rareTierBox = new JCheckBox("Rare", true);
    private final JCheckBox novelTierBox = new JCheckBox("Novel", true);
    private final JSpinner maxResultsSpinner =
        new JSpinner(new SpinnerNumberModel(10000, 1000, 200000, 1000));
    private final JSpinner logCapSpinner =
        new JSpinner(new SpinnerNumberModel(500, 25, 10000, 25));
    private final JLabel retentionInfo = new JLabel(
        "Each retained row keeps the full request/response message; oldest non-candidate rows are pruned first.");
    private final JLabel tierGateInfo = new JLabel(
        "When a tier is unchecked, its techniques are rebuilt disabled (does not affect built-in framing probes).");
    private final JLabel aberrationInfo = new JLabel(
        "Advanced families active: Raw Aberrations, Scheme Tampering, header confusion (Host/:authority, obs-fold).");

    // ─── State ──────────────────────────────────────────────────────────
    private HttpMessage baseMsg;
    private int baselineStatus = -1;
    private int baselineLen = 0;
    private SwingWorker<List<Result>, Object> worker;
    private volatile boolean paused = false;
    private final boolean[] runCancelled = {false};
    private final Object pauseLock = new Object();
    private long runStartTime = 0L;
    private int candidateCount = 0;

    // ─── Persistence (settings + technique toggles) ────────────────────
    private final Map<String, Boolean> persistedFamilyOn = new LinkedHashMap<>();
    private final Set<String> persistedRowsOn = new LinkedHashSet<>();
    private final Set<String> persistedRowsOff = new LinkedHashSet<>();

    // ─── TamperOauth state ─────────────────────────────────────────────
    private OauthEngine.Context oauthContext;
    private SwingWorker<Void, Object> oauthWorker;
    private final boolean[] oauthCancelled = {false};
    private int oauthBaselineStatus = -1;
    private int oauthBaselineLen = 0;

    public HacktorPanel(ExtensionHacktor extension) {
        super();
        this.extension = extension;
        setName("Hacktor");
        setLayout(new BorderLayout(0, 0));
        setBackground(BG);

        Font baseFont = getFont();
        int fs = (baseFont != null) ? baseFont.getSize() : 12;

        // Vulnerability-type filter: the built-in bypass classes plus every
        // vulnerability class from the catalog.
        for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
            vulnTypeCombo.addItem(vc.getFamily());
        }

        // ZAP core HTTP viewers, registered so ZAP can offer their views in Request/Response.
        requestViewer = new HttpPanelRequest(false, "hacktor.request");
        responseViewer = new HttpPanelResponse(false, "hacktor.response");
        registerHttpPanels();

        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);
        tabs.setBackground(BG);
        tabs.setForeground(FG);
        tabs.addTab("Target",     buildTargetTab(fs));
        tabs.addTab("TamperOauth", buildOauthTab(fs));
        tabs.addTab("Techniques", buildTechniquesTab(fs));
        tabs.addTab("Results",    buildResultsTab(fs));
        tabs.addTab("Log",        buildLogTab(fs));
        tabs.addTab("Advanced",   buildAdvancedTab(fs));
        add(tabs, BorderLayout.CENTER);

        themeSelector(filterColumnCombo);
        themeSpinner(timeoutSpinner);
        themeSpinner(maxProbesSpinner);

        wireActions(fs);

        loadOobConfigIntoField();

        // Persisted settings and toggles are applied, then the technique table
        // is always populated (placeholder set until a real target is picked).
        initPersistence();
        rebuildTechniques();

        editTechButton.setEnabled(false);
        removeTechButton.setEnabled(false);
        duplicateTechButton.setEnabled(false);

        // Fuzz-mode-gated controls start disabled until Fuzz Mode is checked.
        fuzzWordlistField.setEnabled(false);
        fuzzBrowseButton.setEnabled(false);
        fuzzUrlBox.setEnabled(false);
        urlModeCombo.setEnabled(false);
        fuzzHeaderBox.setEnabled(false);
        fuzzBodyBox.setEnabled(false);
        customHeaderTable.setEnabled(false);
        addHeaderButton.setEnabled(false);
        removeHeaderButton.setEnabled(false);
        clearHeaderButton.setEnabled(false);
        bodyModeCombo.setEnabled(false);
        bodyTemplateEditor.setEnabled(false);
        formatBodyButton.setEnabled(false);
        addFuzzBodyButton.setEnabled(false);
        loadBodyButton.setEnabled(false);
    }

    // ─── HTTP panel lifecycle ───────────────────────────────────────────

    private void registerHttpPanels() {
        if (!panelsRegistered[0]) {
            HttpPanelManager.getInstance().addRequestPanel(requestViewer);
            HttpPanelManager.getInstance().addResponsePanel(responseViewer);
            panelsRegistered[0] = true;
        }
    }

    /** Releases resources; safe to call multiple times. Called by {@link ExtensionHacktor#unload()}. */
    public void unload() {
        shutdown();
        if (panelsRegistered[0]) {
            try {
                HttpPanelManager.getInstance().removeRequestPanel(requestViewer);
            } catch (Exception ignored) {
            }
            try {
                HttpPanelManager.getInstance().removeResponsePanel(responseViewer);
            } catch (Exception ignored) {
            }
            panelsRegistered[0] = false;
        }
    }

    // ─── Theme helpers ──────────────────────────────────────────────────

    private static void theme(JComponent c) {
        c.setBackground(BG);
        c.setForeground(FG);
        if (c instanceof JTextField) {
            ((JTextField) c).setCaretColor(FG);
        }
    }

    private static void themeSpinner(JSpinner s) {
        s.setBackground(BG);
        s.setForeground(FG);
        s.setEditor(new JSpinner.NumberEditor(s));
        ((JSpinner.DefaultEditor) s.getEditor()).getTextField().setBackground(BG_DARK);
        ((JSpinner.DefaultEditor) s.getEditor()).getTextField().setForeground(FG);
    }

    private static void themeSelector(JComponent c) {
        c.setBackground(BG_DARK);
        c.setForeground(FG);
    }

    private static void themeTable(JTable t) {
        t.setBackground(BG_DARK);
        t.setForeground(FG);
        t.setSelectionBackground(SELECTION);
        t.setSelectionForeground(FG);
        t.setGridColor(BORDER);
        t.getTableHeader().setBackground(BG);
        t.getTableHeader().setForeground(FG);
        t.getTableHeader().setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER));
        t.setRowHeight(22);
        t.setFont(new Font(Font.MONOSPACED, Font.PLAIN, t.getFont().getSize()));
    }

    private static void themeButton(JButton b) {
        b.setBackground(BG);
        b.setForeground(FG);
        b.setFocusPainted(false);
        b.setBorderPainted(true);
        b.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER),
            BorderFactory.createEmptyBorder(4, 10, 4, 10)));
    }

    /**
     * Content pane that always tracks the viewport width so the layout reflows,
     * fills and adjusts to the window instead of overflowing horizontally.
     */
    private static final class TrackWidth extends JPanel implements Scrollable {
        private static final long serialVersionUID = 1L;

        TrackWidth() {
            super();
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return super.getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 12;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 24;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    private static JPanel titledDark(String title, LayoutManager layout) {
        JPanel p = new JPanel(layout);
        p.setBackground(BG_PANEL);
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BORDER),
            BorderFactory.createTitledBorder(
                BorderFactory.createEmptyBorder(), title,
                TitledBorder.LEFT, TitledBorder.TOP,
                new Font(Font.SANS_SERIF, Font.BOLD, 11), FG)));
        return p;
    }

    private static JLabel fieldLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(FG);
        return l;
    }

    private static JLabel dimLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(FG_DIM);
        return l;
    }

    /** A label/component row used inside dialog forms, styled to match the theme. */
    private static JPanel styledPair(JComponent c1, JComponent c2) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBackground(BG);
        c1.setForeground(FG);
        row.add(c1, BorderLayout.WEST);
        row.add(c2, BorderLayout.CENTER);
        return row;
    }

    /** Lightweight pretty-printer for JSON/XML/HTML bodies (2-space indent).
     *  Returns null if the content cannot be parsed; supports JSON objects/arrays
     *  and bracket-structured XML-ish text. */
    private static String prettyPrint(String input) {
        if (input == null) return null;
        String s = input.trim();
        if (s.isEmpty()) return s;
        if (s.startsWith("{") || s.startsWith("[")) {
            return prettyJson(input);
        }
        if (s.startsWith("<")) {
            return prettyXml(input);
        }
        return null;
    }

    private static String prettyJson(String input) {
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (inString) {
                out.append(c);
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
                out.append(c);
                continue;
            }
            if (c == '{' || c == '[') {
                out.append(c).append('\n');
                indent++;
                appendIndent(out, indent);
            } else if (c == '}' || c == ']') {
                out.append('\n');
                indent = Math.max(0, indent - 1);
                appendIndent(out, indent);
                out.append(c);
                if (i + 1 < input.length()
                        && (input.charAt(i + 1) == ',')) {
                    out.append(',');
                    i++;
                }
                out.append('\n');
                appendIndent(out, indent);
            } else if (c == ',') {
                out.append(c).append('\n');
                appendIndent(out, indent);
            } else if (c == ':') {
                out.append(": ");
            } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                // collapse whitespace outside strings
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static void appendIndent(StringBuilder out, int indent) {
        for (int k = 0; k < indent; k++) out.append("  ");
    }

    private static String prettyXml(String input) {
        StringBuilder out = new StringBuilder();
        int indent = 0;
        int i = 0;
        int n = input.length();
        while (i < n) {
            if (input.charAt(i) != '<') {
                StringBuilder text = new StringBuilder();
                while (i < n && input.charAt(i) != '<') text.append(input.charAt(i++));
                String trimmed = text.toString().trim();
                if (!trimmed.isEmpty()) out.append(trimmed);
                continue;
            }
            int end = input.indexOf('>', i);
            if (end < 0) {
                out.append(input.substring(i));
                break;
            }
            String tag = input.substring(i, end + 1);
            boolean closing = tag.startsWith("</");
            boolean selfClosing = tag.endsWith("/>");
            boolean special = tag.startsWith("<!") || tag.startsWith("<?");
            if (!special) {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') {
                    out.append('\n');
                }
                if (closing) indent = Math.max(0, indent - 1);
                appendIndent(out, indent);
                out.append(tag);
                if (!closing && !selfClosing) indent++;
            } else {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '\n') {
                    out.append('\n');
                }
                appendIndent(out, indent);
                out.append(tag);
            }
            i = end + 1;
        }
        return out.toString();
    }

    // ─── Tab builders ───────────────────────────────────────────────────

    // ─── TamperOauth tab ────────────────────────────────────────────────

    private JPanel buildOauthTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(0, 0));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel title = new JLabel("TamperOauth");
        title.setFont(title.getFont().deriveFont(Font.BOLD, fs + 4f));
        title.setForeground(FG);
        JLabel subtitle = new JLabel(
            "OAuth 1.0a / 2.0 / OIDC tamper lab — auto-detects OAuth URLs sent to Hacktor, "
            + "gives full control over URL queries/params/values, and runs Classic/Rare/Novel tamper techniques.");
        subtitle.setFont(subtitle.getFont().deriveFont(fs - 1f));
        subtitle.setForeground(FG_DIM);
        JPanel header = new JPanel(new BorderLayout(6, 0));
        header.setBackground(BG);
        header.add(title, BorderLayout.WEST);
        header.add(subtitle, BorderLayout.CENTER);
        tab.add(header, BorderLayout.NORTH);

        TrackWidth stack = new TrackWidth();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        stack.setBackground(BG);

        stack.add(oauthTargetSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(oauthParamsSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(oauthTechniquesSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(oauthRunSection());

        JScrollPane scroll = new JScrollPane(stack,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(BG);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        tab.add(scroll, BorderLayout.CENTER);
        return tab;
    }

    private JPanel oauthTargetSection() {
        JPanel p = titledDark("OAuth Endpoint", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("Auth URL:"), g);
        g.gridx = 1; g.weightx = 1;
        theme(oauthUrlField);
        oauthUrlField.setToolTipText("Auto-populated from any OAuth request sent to Hacktor, or paste a URL "
            + "and press Detect. Queries, parameters and values below are fully editable.");
        p.add(oauthUrlField, g);
        g.gridx = 2; g.weightx = 0;
        themeButton(oauthDetectButton);
        oauthDetectButton.setToolTipText("Parse the URL above and identify the OAuth endpoint/flow.");
        p.add(oauthDetectButton, g);
        g.gridx = 3;
        themeButton(oauthFromMessageButton);
        oauthFromMessageButton.setToolTipText("Reuse the currently selected message in the Sites tree.");
        p.add(oauthFromMessageButton, g);

        row++;
        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("Endpoint:"), g);
        g.gridx = 1; g.gridwidth = 3;
        oauthEndpointLabel.setForeground(FG_DIM);
        p.add(oauthEndpointLabel, g);
        g.gridwidth = 1;

        row++;
        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("Flow:"), g);
        g.gridx = 1; g.gridwidth = 3;
        oauthFlowLabel.setForeground(CYAN);
        p.add(oauthFlowLabel, g);
        g.gridwidth = 1;
        return p;
    }

    private JPanel oauthParamsSection() {
        JPanel p = titledDark("Parameters & Values", new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel top = new JPanel(new BorderLayout(6, 0));
        top.setBackground(BG_PANEL);
        oauthParamsInfo.setForeground(FG_DIM);
        top.add(oauthParamsInfo, BorderLayout.WEST);
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btns.setBackground(BG_PANEL);
        themeButton(oauthAddParamButton);
        themeButton(oauthRemoveParamButton);
        btns.add(oauthAddParamButton);
        btns.add(oauthRemoveParamButton);
        top.add(btns, BorderLayout.EAST);
        p.add(top, BorderLayout.NORTH);

        oauthParamTable.setShowHorizontalLines(false);
        oauthParamTable.setRowHeight(20);
        JComboBox<String> encCombo = new JComboBox<>(OAUTH_ENCS);
        encCombo.setBackground(BG_DARK);
        encCombo.setForeground(FG);
        oauthParamTable.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(encCombo));
        JScrollPane scroll = new JScrollPane(oauthParamTable);
        scroll.setPreferredSize(new Dimension(200, 150));
        scroll.setBackground(BG);
        p.add(scroll, BorderLayout.CENTER);

        oauthParamModel.addTableModelListener(e -> {
            oauthParamsInfo.setText(oauthParamModel.getRowCount() + " parameters"
                + " \u2014 encoding applied per parameter at technique-build time");
            rebuildOauthTechniques();
        });
        return p;
    }

    private JPanel oauthTechniquesSection() {
        JPanel p = titledDark("Techniques (Classic / Rare / Novel)", new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        top.setBackground(BG_PANEL);
        for (JCheckBox cb : new JCheckBox[]{oauthClassicBox, oauthRareBox, oauthNovelBox}) {
            cb.setBackground(BG_PANEL);
            cb.setForeground(FG);
            cb.addActionListener(e -> rebuildOauthTechniques());
            top.add(cb);
        }
        oauthCountLabel.setForeground(FG_DIM);
        oauthCountLabel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
        top.add(oauthCountLabel);
        p.add(top, BorderLayout.NORTH);

        oauthTechniqueTable.setShowHorizontalLines(false);
        oauthTechniqueTable.setRowHeight(20);
        JScrollPane scroll = new JScrollPane(oauthTechniqueTable);
        scroll.setPreferredSize(new Dimension(200, 190));
        scroll.setBackground(BG);
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private JPanel oauthRunSection() {
        JPanel p = titledDark("Run", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row;
        themeButton(oauthRunButton);
        oauthRunButton.setToolTipText("Send each enabled OAuth tamper technique once against the detected endpoint.");
        p.add(oauthRunButton, g);
        g.gridx = 1;
        themeButton(oauthStopButton);
        oauthStopButton.setToolTipText("Abort the running OAuth tamper run.");
        p.add(oauthStopButton, g);
        g.gridx = 2; g.weightx = 1;
        oauthProgressBar.setStringPainted(true);
        oauthProgressBar.setBackground(BG_DARK);
        oauthProgressBar.setForeground(ACCENT);
        p.add(oauthProgressBar, g);

        row++;
        g.gridx = 0; g.gridy = row; g.gridwidth = 3;
        oauthProgressLabel.setForeground(FG_DIM);
        p.add(oauthProgressLabel, g);
        g.gridwidth = 1;
        return p;
    }

    // ─── TamperOauth actions ────────────────────────────────────────────

    private void onOauthDetectMessage(HttpMessage msg) {
        try {
            OauthEngine.Context ctx = OauthEngine.parse(msg);
            setOauthContext(ctx);
        } catch (Exception ex) {
            appendLog("[!] OAuth detection failed: " + ex.getMessage());
        }
    }

    private void onOauthDetectUrl(String url) {
        if (url == null || url.trim().isEmpty()) return;
        try {
            setOauthContext(OauthEngine.parse(url));
        } catch (Exception ex) {
            appendLog("[!] OAuth detection failed: " + ex.getMessage());
        }
    }

    private void setOauthContext(OauthEngine.Context ctx) {
        oauthContext = ctx;
        if (ctx == null || !ctx.isOAuth()) {
            oauthEndpointLabel.setText("Not detected");
            oauthFlowLabel.setText("—");
            oauthParamsInfo.setText("0 parameters");
            oauthParamModel.setParams(null);
            oauthTechniqueModel.setRows(java.util.Collections.emptyList());
            oauthCountLabel.setText("0 techniques");
            oauthRunButton.setEnabled(false);
            appendLog(ctx == null
                ? "[*] TamperOauth: no OAuth shapes found in the supplied URL."
                : "[*] TamperOauth: request does not look OAuth-shaped.");
            return;
        }
        oauthUrlField.setText(ctx.rawUrl);
        oauthEndpointLabel.setText(ctx.endpoint.getLabel());
        oauthFlowLabel.setText(ctx.flowLabel + " \u2014 " + ctx.params.size() + " param(s), "
            + ctx.oauthParams.size() + " OAuth name(s)");
        oauthParamModel.setParams(ctx.params);
        oauthRunButton.setEnabled(true);
        appendLog("[*] OAuth auto-detected: " + ctx.endpoint.getLabel() + " (" + ctx.flowLabel + ")");
        rebuildOauthTechniques();
    }

    private void rebuildOauthTechniques() {
        if (oauthContext == null || !oauthContext.isOAuth()) {
            oauthTechniqueModel.setRows(java.util.Collections.emptyList());
            oauthCountLabel.setText("0 techniques");
            return;
        }
        Map<String, PayloadEncoder.Encoder> encPref = new LinkedHashMap<>();
        Set<String> canonPref = new LinkedHashSet<>();
        for (int i = 0; i < oauthParamModel.getRowCount(); i++) {
            String name = oauthParamModel.getNameAt(i);
            if (name == null) continue;
            OauthEncoding o = OAUTH_ENC_MAP.get(oauthParamModel.getEncodingAt(i));
            if (o == null) continue;
            if (o.canon) canonPref.add(name);
            if (o.enc != null) encPref.put(name, o.enc);
        }
        List<Technique> techs = new ArrayList<>();
        try {
            for (OauthEngine.OauthTech t : OauthEngine.catalog()) {
                try {
                    for (OauthEngine.Context v : t.generate(oauthContext)) {
                        final OauthEngine.Wire wire =
                            OauthEngine.Wire.prepare(OauthEngine.applyEncode(v, encPref, canonPref));
                        if (wire.literalPathQuery == null) continue;
                        String delta = OauthEngine.summarize(oauthContext, v);
                        Technique tec = new Technique(
                            "OAuth:" + t.category,
                            "[" + tierName(t.tier) + "] " + t.name,
                            t.description + (delta.isEmpty() ? "" : " \u2014 " + delta),
                            base -> {
                                HttpMessage c = base.cloneAll();
                                OauthEngine.buildTarget(c, wire);
                                return c;
                            });
                        tec.setTier(t.tier);
                        tec.setNeedsRawWire(true);
                        techs.add(tec);
                    }
                } catch (Exception ignore) {
                    // catalog entry not applicable in this context
                }
            }
        } catch (Exception ex) {
            appendLog("[!] OAuth technique build failed: " + ex.getMessage());
        }
        applyOauthTierGate(techs);
        oauthTechniqueModel.setRows(techs);
        oauthCountLabel.setText(techs.size() + " techniques");
        appendLog("[*] TamperOauth: " + techs.size() + " OAuth tamper techniques crafted");
    }

    private void applyOauthTierGate(List<Technique> techs) {
        for (Technique t : techs) {
            VulnCatalog.Tier tier = t.getTier();
            boolean on = (tier == VulnCatalog.Tier.CLASSIC && oauthClassicBox.isSelected())
                || (tier == VulnCatalog.Tier.RARE && oauthRareBox.isSelected())
                || (tier == VulnCatalog.Tier.NOVEL && oauthNovelBox.isSelected());
            t.setEnabled(on);
        }
    }

    private void oauthAddParam() {
        if (oauthContext == null) {
            appendLog("[!] Detect an OAuth endpoint first.");
            return;
        }
        String name = JOptionPane.showInputDialog(this, "Parameter name:", "Add OAuth parameter",
            JOptionPane.PLAIN_MESSAGE);
        if (name == null) return;
        name = name.trim();
        if (name.isEmpty()) return;
        String value = JOptionPane.showInputDialog(this, "Value for '" + name + "':",
            "Add OAuth parameter", JOptionPane.PLAIN_MESSAGE);
        value = value == null ? "" : value;
        oauthContext.params.add(new OauthEngine.Param(name, value));
        oauthParamModel.setParams(oauthContext.params);
        rebuildOauthTechniques();
        appendLog("[*] Added OAuth parameter: " + name + " = " + value);
    }

    private void oauthRemoveParam() {
        if (oauthContext == null) return;
        int row = oauthParamTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = oauthParamTable.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= oauthContext.params.size()) return;
        OauthEngine.Param removed = oauthContext.params.remove(modelRow);
        oauthParamModel.setParams(oauthContext.params);
        rebuildOauthTechniques();
        appendLog("[*] Removed OAuth parameter: " + removed.name);
    }

    private HttpMessage buildOauthBaseMessage() throws Exception {
        HttpMessage base;
        if (baseMsg != null) {
            base = baseMsg.cloneAll();
        } else {
            org.apache.commons.httpclient.URI uri =
                new org.apache.commons.httpclient.URI(oauthContext.baseNoQuery, true);
            base = new HttpMessage(uri);
        }
        HacktorEngine.replacePath(base, oauthContext.baseNoQuery);
        if (base.getRequestHeader().getHeader("User-Agent") == null) {
            base.getRequestHeader().setHeader("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        }
        base.getRequestHeader().setHeader("Accept", "*/*");
        return base;
    }

    private void runOauth() {
        if (oauthWorker != null && !oauthWorker.isDone()) {
            appendLog("[*] An OAuth run is already active.");
            return;
        }
        if (oauthContext == null || !oauthContext.isOAuth()) {
            appendLog("[!] No OAuth endpoint detected to tamper.");
            return;
        }
        List<Technique> enabled = oauthTechniqueModel.getAll().stream()
            .filter(Technique::isEnabled).collect(Collectors.toList());
        if (enabled.isEmpty()) {
            appendLog("[!] No OAuth techniques enabled (tick a tier / parameters).");
            return;
        }
        final int maxProbes = (Integer) maxProbesSpinner.getValue();
        if (maxProbes > 0 && enabled.size() > maxProbes) {
            enabled = enabled.subList(0, maxProbes);
            appendLog("[*] Limiting OAuth run to the first " + maxProbes + " enabled techniques.");
        }
        engine.setForceRawWire(useRawWireBox.isSelected());
        engine.setSoTimeoutSeconds((Integer) timeoutSpinner.getValue());
        final List<Technique> runTechs = new ArrayList<>(enabled);
        final int total = runTechs.size();
        final int threadCount = (Integer) threadsSpinner.getValue();
        final int rateLimit = (Integer) rateLimitSpinner.getValue();
        final boolean retryOnError = retryOnErrorBox.isSelected();
        final boolean stopOnCandidate = stopOnCandidateBox.isSelected();
        final boolean backoffEnabled = backoffBox.isSelected();
        oauthCancelled[0] = false;
        oauthRunButton.setEnabled(false);
        oauthStopButton.setEnabled(true);
        oauthProgressBar.setValue(0);
        oauthProgressBar.setMaximum(Math.max(total, 1));
        oauthProgressBar.setString("0 / " + total);
        oauthProgressLabel.setText("Starting...");
        appendLog("[*] TamperOauth: running " + total + " OAuth tamper probes..."
            + (threadCount > 1 ? " [threads: " + threadCount + "]" : "")
            + (rateLimit > 0 ? " [rate: " + rateLimit + "/sec]" : "")
            + (backoffEnabled ? " [exp. backoff]" : "")
            + " [timeout: " + timeoutSpinner.getValue() + "s]");

        oauthWorker = new SwingWorker<Void, Object>() {
            private HttpSender sender;
            private int oBaseStatus = -1;
            private int oBaseLen = 0;
            private String oBaseBody = "";

            @Override
            protected Void doInBackground() throws Exception {
                sender = createSender();
                sender.setFollowRedirect(followRedirectsBox.isSelected());
                HttpMessage base = buildOauthBaseMessage();
                try {
                    int so = (Integer) timeoutSpinner.getValue();
                    if (so > 0) {
                        HttpRequestConfig cfg = HttpRequestConfig.builder()
                            .setSoTimeout(so * 1000).build();
                        sender.sendAndReceive(base, cfg);
                    } else {
                        sender.sendAndReceive(base);
                    }
                } catch (Exception ignore) {
                }
                oBaseStatus = base.getResponseHeader().getStatusCode();
                oBaseBody = base.getResponseBody().toString();
                oBaseLen = oBaseBody.length();
                int cur = 0;
                try {
                    final long minInterval = rateLimit > 0 ? 1000L / rateLimit : 0;
                    if (threadCount <= 1) {
                        final BackoffPacer pacer = backoffEnabled ? new BackoffPacer() : null;
                        long lastRequestTime = 0;
                        for (Technique t : runTechs) {
                            if (isCancelled() || oauthCancelled[0]) break;
                            long now = System.currentTimeMillis();
                            if (minInterval > 0 && lastRequestTime > 0) {
                                long wait = minInterval - (now - lastRequestTime);
                                if (wait > 0) {
                                    try { Thread.sleep(wait); } catch (InterruptedException e) { break; }
                                }
                            }
                            lastRequestTime = System.currentTimeMillis();
                            if (pacer != null) {
                                try { pacer.await(); } catch (InterruptedException e) { break; }
                            }
                            Result r = oauthProbe(base, t, sender, retryOnError);
                            if (pacer != null) pacer.observe(looksThrottled(r));
                            cur++;
                            if (r != null) publish(new Object[]{r, cur, total});
                            if (stopOnCandidate && r != null
                                    && r.getVerdict() == Technique.Verdict.CANDIDATE) {
                                oauthCancelled[0] = true;
                                break;
                            }
                        }
                    } else {
                        final BackoffPacer pacer = backoffEnabled ? new BackoffPacer() : null;
                        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
                        try {
                            java.util.List<Future<Result>> futures = new java.util.ArrayList<>();
                            for (Technique t : runTechs) {
                                if (isCancelled() || oauthCancelled[0]) break;
                                futures.add(pool.submit(() -> {
                                    if (isCancelled() || oauthCancelled[0]) return null;
                                    if (minInterval > 0) oauthSleep(minInterval);
                                    if (pacer != null) {
                                        try { pacer.await(); } catch (InterruptedException e) { return null; }
                                    }
                                    HttpSender s = createSender();
                                    s.setFollowRedirect(followRedirectsBox.isSelected());
                                    try {
                                        Result r = oauthProbe(base, t, s, retryOnError);
                                        if (pacer != null) pacer.observe(looksThrottled(r));
                                        return r;
                                    } finally {
                                        s.shutdown();
                                    }
                                }));
                            }
                            for (Future<Result> f : futures) {
                                if (isCancelled() || oauthCancelled[0]) {
                                    f.cancel(true);
                                    cur++;
                                    publish(new Object[]{null, cur, total});
                                    continue;
                                }
                                Result r;
                                try {
                                    r = f.get(60, TimeUnit.SECONDS);
                                } catch (Exception e) {
                                    r = null;
                                }
                                cur++;
                                if (r != null) publish(new Object[]{r, cur, total});
                                if (stopOnCandidate && r != null
                                        && r.getVerdict() == Technique.Verdict.CANDIDATE) {
                                    oauthCancelled[0] = true;
                                    break;
                                }
                            }
                        } finally {
                            pool.shutdownNow();
                        }
                    }
                } finally {
                    if (sender != null) sender.shutdown();
                }
                return null;
            }

            private Result oauthProbe(HttpMessage base, Technique t, HttpSender s, boolean retry) {
                int attempts = retry ? 3 : 1;
                Result last = null;
                for (int a = 0; a < attempts; a++) {
                    if (a > 0) oauthSleep(250);
                    last = engine.runOne(base, t, s, suppressErrorsBox.isSelected(),
                        oBaseStatus, oBaseLen, oBaseBody);
                    if (last != null || isCancelled() || oauthCancelled[0]) break;
                }
                return last;
            }

            private void oauthSleep(long ms) {
                if (ms <= 0) return;
                try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }

            @Override
            protected void process(List<Object> chunks) {
                int maxCur = oauthProgressBar.getValue();
                for (int i = 0; i < chunks.size(); i += 3) {
                    Result r = (Result) chunks.get(i);
                    int cur = (Integer) chunks.get(i + 1);
                    int tot = (Integer) chunks.get(i + 2);
                    if (cur > maxCur) maxCur = cur;
                    if (r != null) {
                        resultsModel.addResult(r);
                        if (r.getVerdict() == Technique.Verdict.CANDIDATE) {
                            candidateCount++;
                            appendLog(String.format("[!] OAUTH CANDIDATE: %s -> %d (%d bytes)",
                                r.getLabel(), r.getStatus(), r.getLength()));
                        }
                    }
                }
                int tot = oauthProgressBar.getMaximum();
                if (maxCur > tot) maxCur = tot;
                oauthProgressBar.setValue(maxCur);
                oauthProgressBar.setString(maxCur + " / " + tot);
                oauthProgressLabel.setText(String.format("Running: %d/%d (%.0f%%)",
                    maxCur, tot, (maxCur * 100.0) / Math.max(tot, 1)));
            }

            @Override
            protected void done() {
                oauthStopButton.setEnabled(false);
                oauthRunButton.setEnabled(true);
                oauthProgressLabel.setText("Complete.");
                int ran = oauthProgressBar.getValue();
                appendLog("[*] TamperOauth: complete " + ran + "/" + total
                    + " probes \u2014 review the Results tab.");
            }
        };
        oauthWorker.execute();
    }

    private void stopOauth() {
        if (oauthWorker != null && !oauthWorker.isDone()) {
            oauthCancelled[0] = true;
            oauthWorker.cancel(true);
        }
        oauthStopButton.setEnabled(false);
        oauthRunButton.setEnabled(true);
        oauthProgressLabel.setText("Stopped.");
        appendLog("[*] TamperOauth: stopped by user.");
    }

    private static final class OauthEncoding {
        final PayloadEncoder.Encoder enc;
        final boolean canon;
        OauthEncoding(PayloadEncoder.Encoder enc, boolean canon) {
            this.enc = enc;
            this.canon = canon;
        }
    }

    private static final String[] OAUTH_ENCS = {
        "None", "Canonicalize", "URL x1", "URL x2", "URL x3",
        "Base64", "Base64 URL", "ASCII Hex", "Overlong UTF-8"};

    private static final Map<String, OauthEncoding> OAUTH_ENC_MAP = buildOauthEncMap();

    private static Map<String, OauthEncoding> buildOauthEncMap() {
        Map<String, OauthEncoding> m = new HashMap<>();
        m.put("None", new OauthEncoding(null, false));
        m.put("Canonicalize", new OauthEncoding(null, true));
        m.put("URL x1", new OauthEncoding(PayloadEncoder.Encoder.URL1, false));
        m.put("URL x2", new OauthEncoding(PayloadEncoder.Encoder.URL2, false));
        m.put("URL x3", new OauthEncoding(PayloadEncoder.Encoder.URL3, false));
        m.put("Base64", new OauthEncoding(PayloadEncoder.Encoder.B64, false));
        m.put("Base64 URL", new OauthEncoding(PayloadEncoder.Encoder.B64U, false));
        m.put("ASCII Hex", new OauthEncoding(PayloadEncoder.Encoder.HEX, false));
        m.put("Overlong UTF-8", new OauthEncoding(PayloadEncoder.Encoder.OVERLONG, false));
        return m;
    }

    private class OauthParamTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private List<OauthEngine.Param> params = new ArrayList<>();
        private String[] encSel = new String[0];

        void setParams(List<OauthEngine.Param> p) {
            params = p == null ? new ArrayList<>() : p;
            encSel = new String[params.size()];
            java.util.Arrays.fill(encSel, "None");
            fireTableDataChanged();
        }

        List<OauthEngine.Param> getParams() { return params; }

        String getNameAt(int row) { return (row >= 0 && row < params.size()) ? params.get(row).name : null; }
        String getEncodingAt(int row) { return (row >= 0 && row < encSel.length) ? encSel[row] : "None"; }

        @Override public int getRowCount() { return params.size(); }
        @Override public int getColumnCount() { return 4; }
        @Override public String getColumnName(int c) {
            switch (c) {
                case 0: return "Name";
                case 1: return "Value";
                case 2: return "Source";
                case 3: return "Encoding";
                default: return "";
            }
        }
        @Override public Class<?> getColumnClass(int c) { return String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0 || c == 1 || c == 3; }
        @Override public Object getValueAt(int row, int col) {
            if (row >= params.size()) return null;
            OauthEngine.Param p = params.get(row);
            switch (col) {
                case 0: return p.name;
                case 1: return p.value;
                case 2: return p.source == OauthEngine.Source.BODY ? "body" : "query";
                case 3: return getEncodingAt(row);
                default: return null;
            }
        }
        @Override public void setValueAt(Object val, int row, int col) {
            if (row >= params.size()) return;
            OauthEngine.Param p = params.get(row);
            String sv = val == null ? "" : val.toString();
            if (col == 0) p.name = sv;
            else if (col == 1) p.value = sv;
            else if (col == 3) {
                if (row < encSel.length) {
                    encSel[row] = sv;
                } else {
                    String[] ne = new String[row + 1];
                    java.util.Arrays.fill(ne, "None");
                    System.arraycopy(encSel, 0, ne, 0, encSel.length);
                    encSel = ne;
                    encSel[row] = sv;
                }
            }
            fireTableDataChanged();
            rebuildOauthTechniques();
        }
    }

    private JPanel buildTargetTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(0, 0));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel title = new JLabel("Hacktor");
        title.setFont(title.getFont().deriveFont(Font.BOLD, fs + 4f));
        title.setForeground(FG);
        JLabel subtitle = new JLabel(
            "Probe 401/403 authorization bypass techniques against the selected request.");
        subtitle.setFont(subtitle.getFont().deriveFont(fs - 1f));
        subtitle.setForeground(FG_DIM);
        JPanel header = new JPanel(new BorderLayout(6, 0));
        header.setBackground(BG);
        header.add(title, BorderLayout.WEST);
        header.add(subtitle, BorderLayout.CENTER);
        tab.add(header, BorderLayout.NORTH);

        TrackWidth stack = new TrackWidth();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        stack.setBackground(BG);

        stack.add(targetSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(fuzzSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(probeOptionsSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(oobSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(runControlsSection());

        JScrollPane scroll = new JScrollPane(stack,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(BG);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        tab.add(scroll, BorderLayout.CENTER);
        return tab;
    }

    private JPanel targetSection() {
        JPanel p = titledDark("Target", new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("URL:"), g);
        g.gridx = 1; g.weightx = 1;
        theme(urlField); urlField.setToolTipText("The URL to probe. Populated from " +
            "‘From Selected’ or by typing here and fetching a baseline.");
        p.add(urlField, g);
        g.gridx = 2; g.weightx = 0;
        themeButton(fromMessageButton);
        fromMessageButton.setToolTipText("Use the currently selected message in the Sites tree.");
        p.add(fromMessageButton, g);
        g.gridx = 3;
        themeButton(fetchButton);
        fetchButton.setToolTipText("Send the request once to record the baseline status/length.");
        p.add(fetchButton, g);

        row++;
        g.gridx = 0; g.gridy = row; g.gridwidth = 4; g.weightx = 1;
        baselineLabel.setForeground(FG_DIM);
        p.add(baselineLabel, g);
        g.gridwidth = 1; g.weightx = 0;

        return p;
    }

    private JPanel fuzzSection() {
        JPanel p = titledDark("Fuzz Mode", new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel north = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;

        g.gridx = 0; g.gridy = 0;
        fuzzModeBox.setToolTipText("Enable to replace FUZZ (or a per-rule Find string) with each word from a wordlist; "
            + "one direct request is sent per word (no bypass techniques)");
        fuzzModeBox.setBackground(BG_PANEL);
        fuzzModeBox.setForeground(FG);
        north.add(fuzzModeBox, g);
        g.gridx = 1; g.weightx = 1;
        theme(fuzzWordlistField);
        fuzzWordlistField.setToolTipText("Wordlist file (one entry per line); each word is substituted for FUZZ / Find");
        fuzzWordlistField.setPreferredSize(new Dimension(320, fuzzWordlistField.getPreferredSize().height));
        north.add(fuzzWordlistField, g);
        g.gridx = 2; g.weightx = 0;
        themeButton(fuzzBrowseButton);
        north.add(fuzzBrowseButton, g);
        g.gridx = 3; g.weightx = 0;
        north.add(dimLabel("one request per word"), g);

        g.gridx = 0; g.gridy = 1; g.gridwidth = 4;
        JPanel types = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        types.setBackground(BG_PANEL);
        types.add(fuzzUrlBox);
        urlModeCombo.setBackground(BG_DARK);
        urlModeCombo.setForeground(FG);
        urlModeCombo.setToolTipText("REPLACE = FUZZ→word; APPEND = add word after URL; PREPEND = add word before URL");
        types.add(urlModeCombo);
        for (JCheckBox cb : new JCheckBox[]{fuzzHeaderBox, fuzzBodyBox}) {
            cb.setBackground(BG_PANEL);
            cb.setForeground(FG);
            types.add(cb);
        }
        types.add(dimLabel("Select which parts of the request to fuzz"));
        north.add(types, g);
        g.gridwidth = 1;
        p.add(north, BorderLayout.NORTH);

        JPanel stack = new JPanel();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        stack.setBackground(BG_PANEL);
        stack.add(Box.createVerticalStrut(4));
        stack.add(headerFuzzPanel());
        stack.add(Box.createVerticalStrut(8));
        stack.add(bodyFuzzPanel());
        p.add(stack, BorderLayout.CENTER);
        return p;
    }

    private JPanel probeOptionsSection() {
        JPanel p = titledDark("Probe Options", new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;

        // Row 1 - behavior / transport toggles
        int col = 0;
        followRedirectsBox.setToolTipText("Follow redirects while fetching the baseline and probing.");
        suppressErrorsBox.setToolTipText("Treat 2xx/3xx/404 responses that look like branded error pages as suppressed.");
        stopOnCandidateBox.setToolTipText("Abort the run as soon as the first CANDIDATE verdict is produced.");
        retryOnErrorBox.setToolTipText("Re-send a probe (up to 3 attempts) when the request fails at the network level.");
        useRawWireBox.setToolTipText("Force every probe through the raw-socket sender so the exact bytes "
            + "reach the server/proxy (best-effort, falls back to ZAP's sender on failure).");
        backoffBox.setToolTipText("Exponential backoff: when the server starts flagging these probes "
            + "(HTTP 429, or a 403 rate-limit/WAF block page), space requests out with exponentially "
            + "growing delays (1s up to 30s) that decay back down once the flag stops.");
        for (JCheckBox cb : new JCheckBox[]{followRedirectsBox, suppressErrorsBox,
                stopOnCandidateBox, retryOnErrorBox, useRawWireBox, backoffBox}) {
            cb.setBackground(BG_PANEL);
            cb.setForeground(FG);
            g.gridx = col++;
            p.add(cb, g);
        }
        g.gridx = col; g.weightx = 1;
        p.add(Box.createHorizontalGlue(), g);
        g.weightx = 0;

        // Row 2 - pacing knobs
        col = 0;
        g.gridy = 1;
        rateLimitLabel.setForeground(FG);
        rateLimitLabel.setToolTipText("Cap the request rate. 0 = unlimited.");
        g.gridx = col++;
        p.add(rateLimitLabel, g);
        g.gridx = col++;
        rateLimitSpinner.setPreferredSize(new Dimension(64, rateLimitSpinner.getPreferredSize().height));
        p.add(rateLimitSpinner, g);
        g.gridx = col++;
        p.add(dimLabel("req/sec (0 = unlimited)"), g);

        g.gridx = col++;
        p.add(Box.createHorizontalStrut(18), g);

        threadsLabel.setForeground(FG);
        threadsLabel.setToolTipText("Parallel probe workers (1-16). 1 runs serially keeping probe order.");
        g.gridx = col++;
        p.add(threadsLabel, g);
        g.gridx = col++;
        threadsSpinner.setPreferredSize(new Dimension(64, threadsSpinner.getPreferredSize().height));
        p.add(threadsSpinner, g);

        g.gridx = col; g.weightx = 1;
        p.add(Box.createHorizontalGlue(), g);
        g.weightx = 0;

        // Row 3 - limits & per-probe timeout
        col = 0;
        g.gridy = 2;
        maxProbesLabel.setToolTipText("Limit the run to this many probes (0 = all). Caps words in Fuzz Mode, techniques otherwise.");
        maxProbesLabel.setForeground(FG);
        g.gridx = col++;
        p.add(maxProbesLabel, g);
        g.gridx = col++;
        maxProbesSpinner.setPreferredSize(new Dimension(64, maxProbesSpinner.getPreferredSize().height));
        p.add(maxProbesSpinner, g);
        g.gridx = col++;
        p.add(dimLabel("probes (0 = all)"), g);

        g.gridx = col++;
        p.add(Box.createHorizontalStrut(18), g);

        timeoutLabel.setForeground(FG);
        timeoutLabel.setToolTipText("Per-probe socket timeout in seconds.");
        g.gridx = col++;
        p.add(timeoutLabel, g);
        g.gridx = col++;
        timeoutSpinner.setPreferredSize(new Dimension(64, timeoutSpinner.getPreferredSize().height));
        p.add(timeoutSpinner, g);
        g.gridx = col++;
        p.add(dimLabel("sec"), g);

        g.gridx = col; g.weightx = 1;
        p.add(Box.createHorizontalGlue(), g);
        g.weightx = 0;
        return p;
    }

    /** Adaptive probe pacing: after the server starts flagging/blocking our requests
     *  (HTTP 429 or a 403 rate-limit/WAF block page), space probes out with exponentially
     *  growing delays. Clean responses halve the current delay so pacing recovers the
     *  moment the flag stops. Shared safely across parallel workers. */
    private static final class BackoffPacer {
        private static final long BASE_MS = 1000L;
        private static final long MAX_MS = 30000L;
        private long delayMs = 0;
        private volatile long backoffUntil = 0;

        BackoffPacer() {}

        void observe(boolean throttled) {
            synchronized (this) {
                if (throttled) {
                    delayMs = delayMs == 0 ? BASE_MS : Math.min(MAX_MS, delayMs * 2);
                    backoffUntil = System.currentTimeMillis() + delayMs;
                } else {
                    delayMs = delayMs <= 0 ? 0 : delayMs / 2;
                }
            }
        }

        /** Blocks until the current backoff window has elapsed (no-op when idle). */
        void await() throws InterruptedException {
            long remain = backoffUntil - System.currentTimeMillis();
            while (remain > 0) {
                Thread.sleep(Math.min(remain, 500));
                remain = backoffUntil - System.currentTimeMillis();
            }
        }
    }

    /** Body markers used to recognise a rate-limit / WAF block page behind an HTTP 403. */
    private static final String[] THROTTLE_KEYWORDS = {
        "rate limit", "rate-limit", "too many requests", "request limit",
        "many requests", "blocked", "access denied", "security check",
        "captcha", "challenge", "unusual activity", "try again later"
    };

    /** True when a probe response looks like the server flagged/blocked the request. */
    private static boolean looksThrottled(Result r) {
        if (r == null) return false;
        int status = r.getStatus();
        if (status == 429) return true;
        if (status != 403) return false;
        String body = r.getBodySample();
        if (body == null) return false;
        String s = body.toLowerCase(Locale.ROOT);
        for (String kw : THROTTLE_KEYWORDS) {
            if (s.contains(kw)) return true;
        }
        return false;
    }

    private JPanel headerFuzzPanel() {
        JPanel p = titledDark(
            "Headers (fuzzed when 'Headers' is selected; Find replaces that string in the header's value; blank = FUZZ)",
            new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        buttonRow.setBackground(BG_PANEL);
        themeButton(addHeaderButton);
        addHeaderButton.setToolTipText("Add a header rule (Find string is replaced by each wordlist entry)");
        buttonRow.add(addHeaderButton);
        themeButton(removeHeaderButton);
        removeHeaderButton.setToolTipText("Remove the selected header rule");
        buttonRow.add(removeHeaderButton);
        themeButton(clearHeaderButton);
        clearHeaderButton.setToolTipText("Remove all header rules");
        buttonRow.add(clearHeaderButton);
        JPanel north = new JPanel(new BorderLayout());
        north.setBackground(BG_PANEL);
        north.add(buttonRow, BorderLayout.WEST);
        north.add(dimLabel("Find in the existing header value -> replaced per word; SET/APPEND/PREPEND merge the result"),
            BorderLayout.EAST);
        p.add(north, BorderLayout.NORTH);

        themeTable(customHeaderTable);
        customHeaderTable.getColumnModel().getColumn(0).setPreferredWidth(160);
        customHeaderTable.getColumnModel().getColumn(1).setPreferredWidth(200);
        customHeaderTable.getColumnModel().getColumn(2).setPreferredWidth(90);
        customHeaderTable.setRowHeight(22);
        JComboBox<String> modeBox = new JComboBox<>(new String[]{"SET", "APPEND", "PREPEND"});
        modeBox.setBackground(BG_DARK);
        customHeaderTable.getColumnModel().getColumn(2).setCellEditor(
            new DefaultCellEditor(modeBox));
        JScrollPane scroll = new JScrollPane(customHeaderTable);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setPreferredSize(new Dimension(0, 90));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private JPanel bodyFuzzPanel() {
        JPanel p = titledDark(
            "Body (fuzzed when 'Body' is selected; highlight text and press 'Add FUZZ', or type FUZZ directly)",
            new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        buttonRow.setBackground(BG_PANEL);
        themeButton(formatBodyButton);
        formatBodyButton.setToolTipText("Re-indent the body (JSON/XML-ish pretty-print)");
        buttonRow.add(formatBodyButton);
        themeButton(addFuzzBodyButton);
        addFuzzBodyButton.setToolTipText("Replace the selected text with FUZZ so each wordlist entry is substituted");
        buttonRow.add(addFuzzBodyButton);
        themeButton(loadBodyButton);
        loadBodyButton.setToolTipText("Load the base request's body into the editor");
        buttonRow.add(loadBodyButton);
        buttonRow.add(dimLabel("Mode:"));
        bodyModeCombo.setBackground(BG_DARK);
        bodyModeCombo.setForeground(FG);
        bodyModeCombo.setToolTipText("REPLACE = fuzzed body is used as-is; "
            + "APPEND = fuzzed body appended after the original body; PREPEND = fuzzed body inserted before it");
        buttonRow.add(bodyModeCombo);
        JPanel north = new JPanel(new BorderLayout());
        north.setBackground(BG_PANEL);
        north.add(buttonRow, BorderLayout.WEST);
        p.add(north, BorderLayout.NORTH);

        bodyTemplateEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        bodyTemplateEditor.setCodeFoldingEnabled(true);
        bodyTemplateEditor.setAntiAliasingEnabled(true);
        bodyTemplateEditor.setTabSize(2);
        try {
            org.fife.ui.rsyntaxtextarea.Theme.load(
                RSyntaxTextArea.class.getResourceAsStream(
                    "/org/fife/ui/rsyntaxtextarea/themes/dark.xml")
            ).apply(bodyTemplateEditor);
        } catch (Exception ignored) {
        }
        JScrollPane scroll = new JScrollPane(bodyTemplateEditor);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setPreferredSize(new Dimension(0, 120));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private JPanel oobSection() {
        JPanel p = titledDark("Out-of-Band Callbacks", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("Callback URL:"), g);
        g.gridx = 1; g.weightx = 1;
        theme(oobUrlField);
        oobUrlField.setToolTipText("Your out-of-band interaction server (Burp Collaborator / Interactsh / Canarytokens). "
            + "Saved persistently in ZAP config; every class with OOB probes replaces the "
            + "{{OOB}} placeholder with this URL at rebuild time. Empty disables OOB probes.");
        oobUrlField.setEditable(true);
        p.add(oobUrlField, g);
        g.gridx = 2; g.weightx = 0;
        themeButton(oobSaveButton);
        oobSaveButton.setEnabled(false);
        p.add(oobSaveButton, g);

        row++;
        g.gridx = 0; g.gridy = row; g.gridwidth = 3; g.weightx = 1;
        oobStatusLabel.setForeground(FG_DIM);
        p.add(oobStatusLabel, g);
        g.gridwidth = 1; g.weightx = 0;

        oobUrlField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { oobDirty(); }
            @Override public void removeUpdate(DocumentEvent e) { oobDirty(); }
            @Override public void changedUpdate(DocumentEvent e) { oobDirty(); }
        });
        oobSaveButton.addActionListener(e -> saveOobUrlField());
        return p;
    }

    // ─── OOB persistence ───────────────────────────────────────────────

    private void oobDirty() {
        oobSaveButton.setEnabled(true);
        oobStatusLabel.setForeground(FG);
        oobStatusLabel.setText("Unsaved changes \u2014 press \"Save OOB URL\"");
    }

    private void saveOobUrlField() {
        String url = oobUrlField.getText().trim();
        if (saveOobConfig(url)) {
            engine.setOobUrl(url);
            oobSaveButton.setEnabled(false);
            oobStatusLabel.setForeground(FG_DIM);
            oobStatusLabel.setText(url.isEmpty()
                ? "OOB callbacks: cleared (persisted)"
                : "OOB callbacks: saved (persisted) — " + url);
            appendLog("[*] OOB callback URL " + (url.isEmpty() ? "cleared" : "saved") + ": "
                + (url.isEmpty() ? "(none)" : url));
            rebuildTechniques();
        } else {
            oobStatusLabel.setForeground(RED);
            oobStatusLabel.setText("Failed to persist OOB URL \u2014 check ZAP config");
        }
    }

    private void loadOobConfigIntoField() {
        if (oobUrlField == null) return;
        String url = loadOobConfig();
        oobUrlField.setText(url);
        engine.setOobUrl(url);
        oobSaveButton.setEnabled(false);
        oobStatusLabel.setForeground(FG_DIM);
        oobStatusLabel.setText(url.isEmpty()
            ? "OOB callbacks: not configured"
            : "OOB callbacks: " + url);
    }

    private static String loadOobConfig() {
        try {
            org.apache.commons.configuration.Configuration cfg =
                Model.getSingleton().getOptionsParam().getConfig();
            return cfg == null ? "" : cfg.getString("hacktor.oobUrl", "").trim();
        } catch (Exception ex) {
            return "";
        }
    }

    /** Persists the callback URL into ZAP's global config and saves it immediately. */
    private static boolean saveOobConfig(String url) {
        try {
            org.apache.commons.configuration.FileConfiguration cfg =
                Model.getSingleton().getOptionsParam().getConfig();
            if (cfg == null) return false;
            cfg.setProperty("hacktor.oobUrl", url == null ? "" : url.trim());
            try {
                cfg.save();
            } catch (Exception ignored) {
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private JPanel runControlsSection() {
        JPanel p = titledDark("Run", new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel runRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        runRow.setBackground(BG_PANEL);
        themeButton(runButton);
        runRow.add(runButton);
        themeButton(pauseButton);
        runRow.add(pauseButton);
        themeButton(resumeButton);
        runRow.add(resumeButton);
        themeButton(stopButton);
        runRow.add(stopButton);
        p.add(runRow, BorderLayout.NORTH);

        progressBar.setStringPainted(true);
        progressBar.setBackground(BG_DARK);
        progressBar.setForeground(ACCENT);
        progressBar.setBorder(BorderFactory.createLineBorder(BORDER));
        p.add(progressBar, BorderLayout.CENTER);

        JPanel labelRow = new JPanel(new BorderLayout());
        labelRow.setBackground(BG_PANEL);
        progressLabel.setForeground(FG_DIM);
        labelRow.add(progressLabel, BorderLayout.WEST);
        statsLabel.setForeground(CYAN);
        labelRow.add(statsLabel, BorderLayout.EAST);
        p.add(labelRow, BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildTechniquesTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(6, 6));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel topRow = new JPanel(new BorderLayout(6, 0));
        topRow.setBackground(BG);

        // ─── Compact filter bar ──────────────────────────────────────────
        JPanel filterBar = new JPanel(new BorderLayout(4, 0));
        filterBar.setBackground(BG);

        themeSelector(vulnTypeCombo);
        vulnTypeCombo.setToolTipText("Filter by vulnerability category");
        vulnTypeCombo.setPreferredSize(new Dimension(120, vulnTypeCombo.getPreferredSize().height));
        filterBar.add(vulnTypeCombo, BorderLayout.WEST);

        filterField.setToolTipText("Filter techniques by the selected column");
        filterField.putClientProperty("JTextField.placeholderText", "Filter\u2026");
        filterBar.add(filterField, BorderLayout.CENTER);

        showCustomOnlyBox.setToolTipText("Only show user-defined techniques");
        showCustomOnlyBox.setBackground(BG);
        showCustomOnlyBox.setForeground(FG);

        JPanel filterRight = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        filterRight.setBackground(BG);
        themeSelector(filterColumnCombo);
        filterColumnCombo.setPreferredSize(new Dimension(80, filterColumnCombo.getPreferredSize().height));
        filterRight.add(filterColumnCombo);
        filterRight.add(showCustomOnlyBox);
        filterBar.add(filterRight, BorderLayout.EAST);

        topRow.add(filterBar, BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        btns.setBackground(BG);
        themeButton(addTechButton); btns.add(addTechButton);
        themeButton(duplicateTechButton); btns.add(duplicateTechButton);
        themeButton(editTechButton); btns.add(editTechButton);
        themeButton(removeTechButton); btns.add(removeTechButton);
        btns.add(Box.createHorizontalStrut(12));
        themeButton(enableAllButton); btns.add(enableAllButton);
        themeButton(disableAllButton); btns.add(disableAllButton);
        themeButton(invertButton); btns.add(invertButton);
        topRow.add(btns, BorderLayout.EAST);
        tab.add(topRow, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(0, 4));
        center.setBackground(BG);

        familyPanel.setBackground(BG);
        JScrollPane familyScroll = new JScrollPane(familyPanel);
        familyScroll.setPreferredSize(new Dimension(0, 36));
        familyScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        familyScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        familyScroll.getViewport().setBackground(BG);
        center.add(familyScroll, BorderLayout.NORTH);

        themeTable(techniqueTable);
        techniqueTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        techniqueTable.getColumnModel().getColumn(0).setMaxWidth(30);
        techniqueTable.getColumnModel().getColumn(1).setPreferredWidth(120);
        techniqueTable.getColumnModel().getColumn(2).setPreferredWidth(220);
        techniqueTable.getColumnModel().getColumn(3).setPreferredWidth(0);

        techniqueTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() > 1) return;
                int col = techniqueTable.columnAtPoint(e.getPoint());
                int row = techniqueTable.rowAtPoint(e.getPoint());
                if (col == 0 && row >= 0) {
                    toggleTechnique(row);
                }
            }
        });
        techniqueTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
                    int row = techniqueTable.getSelectedRow();
                    if (row >= 0) toggleTechnique(row);
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(techniqueTable);
        tableScroll.getViewport().setBackground(BG_DARK);
        center.add(tableScroll, BorderLayout.CENTER);

        techniqueSummary.setForeground(FG_DIM);
        JPanel bottomRow = new JPanel(new BorderLayout(6, 0));
        bottomRow.setBackground(BG);
        bottomRow.add(techniqueSummary, BorderLayout.WEST);
        center.add(bottomRow, BorderLayout.SOUTH);
        tab.add(center, BorderLayout.CENTER);

        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyTechniqueFilter(); }
            public void removeUpdate(DocumentEvent e) { applyTechniqueFilter(); }
            public void changedUpdate(DocumentEvent e) { applyTechniqueFilter(); }
        });
        filterColumnCombo.addActionListener(e -> applyTechniqueFilter());
        showCustomOnlyBox.addActionListener(e -> applyTechniqueFilter());
        vulnTypeCombo.addActionListener(e -> applyTechniqueFilter());
        return tab;
    }

    private JPanel buildResultsTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(0, 0));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Top: filter + summary + action buttons
        JPanel north = new JPanel(new BorderLayout(6, 4));
        north.setBackground(BG);

        JPanel filterBar = new JPanel(new BorderLayout(4, 0));
        filterBar.setBackground(BG);
        filterBar.add(fieldLabel("Filter: "), BorderLayout.WEST);
        theme(resultsFilterField);
        resultsFilterField.setToolTipText("Filter results by technique, category, path or verdict");
        filterBar.add(resultsFilterField, BorderLayout.CENTER);
        candidatesOnlyBox.setToolTipText("Show only CANDIDATE results");
        candidatesOnlyBox.setBackground(BG);
        candidatesOnlyBox.setForeground(FG);
        errorsOnlyBox.setToolTipText("Show only results whose status is 400 or higher");
        errorsOnlyBox.setBackground(BG);
        errorsOnlyBox.setForeground(FG);
        JPanel checks = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        checks.setBackground(BG);
        checks.add(candidatesOnlyBox);
        checks.add(errorsOnlyBox);
        JPanel filterCenter = new JPanel(new BorderLayout(6, 0));
        filterCenter.setBackground(BG);
        filterCenter.add(filterBar, BorderLayout.CENTER);
        filterCenter.add(checks, BorderLayout.EAST);
        north.add(filterCenter, BorderLayout.NORTH);

        summaryLabel.setForeground(FG_DIM);
        JPanel summaryPad = new JPanel(new BorderLayout());
        summaryPad.setBackground(BG);
        summaryPad.add(summaryLabel, BorderLayout.WEST);
        north.add(summaryPad, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        buttons.setBackground(BG);
        themeButton(resendButton);
        resendButton.setToolTipText("Re-send the selected probe and refresh its status/length");
        buttons.add(resendButton);
        themeButton(copyUrlButton);
        copyUrlButton.setToolTipText("Copy the selected probe's path/URL to the clipboard");
        buttons.add(copyUrlButton);
        themeButton(copyCurlButton);
        copyCurlButton.setToolTipText("Copy the selected probe as a curl command");
        buttons.add(copyCurlButton);
        themeButton(clearResultsButton);
        clearResultsButton.setToolTipText("Clear the results table and viewers");
        buttons.add(clearResultsButton);
        themeButton(exportButton);
        exportButton.setToolTipText("Export all results to a CSV file");
        buttons.add(exportButton);
        north.add(buttons, BorderLayout.SOUTH);
        tab.add(north, BorderLayout.NORTH);

        // Table (top) + request/response ZAP core viewers (bottom)
        themeTable(resultsTable);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(34);
        resultsTable.getColumnModel().getColumn(0).setMaxWidth(34);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(170);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(170);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(50);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(50);
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(50);
        resultsTable.getColumnModel().getColumn(7).setPreferredWidth(90);
        resultsTable.getColumnModel().getColumn(8).setPreferredWidth(60);
        resultsTable.getColumnModel().getColumn(9).setPreferredWidth(60);

        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.getViewport().setBackground(BG_DARK);

        JLabel reqLbl = new JLabel("Request");
        reqLbl.setFont(LABEL_H2);
        reqLbl.setForeground(ACCENT_LIGHT);
        JLabel respLbl = new JLabel("Response");
        respLbl.setFont(LABEL_H2);
        respLbl.setForeground(ACCENT_LIGHT);

        JPanel reqPane = new JPanel(new BorderLayout(0, 0));
        reqPane.setBackground(BG_DARK);
        JPanel reqHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        reqHeader.setBackground(BG_DARK);
        reqHeader.add(reqLbl, BorderLayout.NORTH);
        reqPane.add(reqHeader, BorderLayout.NORTH);
        reqPane.add(requestViewer, BorderLayout.CENTER);

        JPanel respPane = new JPanel(new BorderLayout(0, 0));
        respPane.setBackground(BG_DARK);
        JPanel respHeader = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 4));
        respHeader.setBackground(BG_DARK);
        respHeader.add(respLbl, BorderLayout.NORTH);
        respPane.add(respHeader, BorderLayout.NORTH);
        respPane.add(responseViewer, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPane, respPane);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerLocation(0.5);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(BorderFactory.createLineBorder(BORDER));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, reqRespSplit);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerLocation(0.55);
        mainSplit.setBackground(BG);
        mainSplit.setBorder(BorderFactory.createLineBorder(BORDER));
        tab.add(mainSplit, BorderLayout.CENTER);

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            showSelectedResult();
        });

        resultsFilterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyResultsFilter(); }
            public void removeUpdate(DocumentEvent e) { applyResultsFilter(); }
            public void changedUpdate(DocumentEvent e) { applyResultsFilter(); }
        });
        candidatesOnlyBox.addActionListener(e -> applyResultsFilter());
        errorsOnlyBox.addActionListener(e -> applyResultsFilter());
        return tab;
    }

    private JPanel buildLogTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(6, 6));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        tab.add(new JScrollPane(logArea), BorderLayout.CENTER);
        return tab;
    }

    // ─── Advanced tab ───────────────────────────────────────────────────

    private JPanel buildAdvancedTab(int fs) {
        JPanel tab = new JPanel(new BorderLayout(0, 0));
        tab.setBackground(BG);
        tab.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        TrackWidth stack = new TrackWidth();
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        stack.setBackground(BG);

        stack.add(tierGateSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(fixedHeadersSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(retentionSection());
        stack.add(Box.createVerticalStrut(8));
        stack.add(informationSection());

        JScrollPane scroll = new JScrollPane(stack,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getViewport().setBackground(BG);
        scroll.getVerticalScrollBar().setUnitIncrement(12);
        tab.add(scroll, BorderLayout.CENTER);
        return tab;
    }

    private JPanel fixedHeadersSection() {
        JPanel p = titledDark(
            "Request Headers (sent with every probe request)",
            new BorderLayout(6, 4));
        p.setBackground(BG_PANEL);

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        buttonRow.setBackground(BG_PANEL);
        themeButton(addFixedHeaderButton);
        addFixedHeaderButton.setToolTipText("Add a fixed header sent with every probe request");
        buttonRow.add(addFixedHeaderButton);
        themeButton(removeFixedHeaderButton);
        removeFixedHeaderButton.setToolTipText("Remove the selected fixed header");
        buttonRow.add(removeFixedHeaderButton);
        JPanel north = new JPanel(new BorderLayout());
        north.setBackground(BG_PANEL);
        north.add(buttonRow, BorderLayout.WEST);
        north.add(dimLabel("Set on every probe and the baseline request; name and value are editable in place"),
            BorderLayout.EAST);
        p.add(north, BorderLayout.NORTH);

        themeTable(fixedHeaderTable);
        fixedHeaderTable.getColumnModel().getColumn(0).setPreferredWidth(180);
        fixedHeaderTable.getColumnModel().getColumn(1).setPreferredWidth(260);
        fixedHeaderTable.setRowHeight(22);
        JScrollPane scroll = new JScrollPane(fixedHeaderTable);
        scroll.getViewport().setBackground(BG_DARK);
        scroll.setPreferredSize(new Dimension(0, 90));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private JPanel tierGateSection() {
        JPanel p = titledDark("Injection Tier Gate", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row; g.gridwidth = 4;
        tierGateInfo.setForeground(FG_DIM);
        p.add(tierGateInfo, g);
        g.gridwidth = 1;

        row++;
        g.gridx = 0; g.gridy = row;
        theme(classicTierBox); classicTierBox.setBackground(BG_PANEL);
        classicTierBox.setToolTipText("Classic payloads: documented in textbooks and OWASP references.");
        p.add(classicTierBox, g);
        g.gridx = 1;
        theme(rareTierBox); rareTierBox.setBackground(BG_PANEL);
        rareTierBox.setToolTipText("Rare payloads: unusual encodings and less common sinks.");
        p.add(rareTierBox, g);
        g.gridx = 2;
        theme(novelTierBox); novelTierBox.setBackground(BG_PANEL);
        novelTierBox.setToolTipText("Novel payloads: unexpected-by-server forms (double-encoded, obfuscated, edge-case).");
        p.add(novelTierBox, g);

        classicTierBox.addActionListener(e -> onTierGateChanged());
        rareTierBox.addActionListener(e -> onTierGateChanged());
        novelTierBox.addActionListener(e -> onTierGateChanged());
        return p;
    }

    private JPanel retentionSection() {
        JPanel p = titledDark("Memory Retention", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 0;
        int row = 0;

        g.gridx = 0; g.gridy = row;
        p.add(fieldLabel("Max results:"), g);
        g.gridx = 1; g.weightx = 0.4;
        themeSpinner(maxResultsSpinner);
        maxResultsSpinner.setToolTipText("Hard cap on retained rows. Each row keeps the full request/response message; "
            + "oldest non-candidate rows are pruned first beyond this limit.");
        p.add(maxResultsSpinner, g);
        g.gridx = 2; g.weightx = 1;
        JLabel resultsHint = new JLabel("rows (keeps request+response detail for candidates)");
        resultsHint.setForeground(FG_DIM);
        p.add(resultsHint, g);

        row++;
        g.gridx = 0; g.gridy = row; g.weightx = 0;
        p.add(fieldLabel("Log cap:"), g);
        g.gridx = 1;
        themeSpinner(logCapSpinner);
        logCapSpinner.setToolTipText("Maximum Log tab size in KB; the tail is kept beyond this bound.");
        p.add(logCapSpinner, g);
        g.gridx = 2; g.weightx = 1;
        JLabel logHint = new JLabel("KB (Log tab tail is truncated beyond this bound)");
        logHint.setForeground(FG_DIM);
        p.add(logHint, g);

        g.gridwidth = 3; g.gridx = 0;
        row++;
        g.gridy = row;
        retentionInfo.setForeground(FG_DIM);
        p.add(retentionInfo, g);

        maxResultsSpinner.addChangeListener(e -> {
            resultsModel.setMaxResults((Integer) maxResultsSpinner.getValue());
            appendLog("[*] Max retained results set to " + maxResultsSpinner.getValue());
        });
        return p;
    }

    private JPanel informationSection() {
        JPanel p = titledDark("Advanced Families", new GridBagLayout());
        p.setBackground(BG_PANEL);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = INS;
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;
        g.gridx = 0; g.gridy = 0;
        aberrationInfo.setForeground(FG_DIM);
        p.add(aberrationInfo, g);
        return p;
    }

    private boolean tierAllowed(Technique t) {
        switch (t.getTier()) {
            case CLASSIC: return classicTierBox.isSelected();
            case RARE:    return rareTierBox.isSelected();
            case NOVEL:   return novelTierBox.isSelected();
            default:      return true;
        }
    }

    /** Strict per-tier on/off gate applied to the live technique list. */
    private void onTierGateChanged() {
        for (Technique t : techniqueModel.getAll()) {
            t.setEnabled(tierAllowed(t));
        }
        techniqueModel.fireTableDataChanged();
        updateCounts();
        syncFamilyBoxes();
        appendLog("[*] Tier gate: Classic=" + classicTierBox.isSelected()
            + " Rare=" + rareTierBox.isSelected()
            + " Novel=" + novelTierBox.isSelected());
    }

    /** Applies the tier gate to a freshly built technique list (before it becomes visible). */
    private void applyTierGate(List<Technique> techs) {
        for (Technique t : techs) {
            if (!tierAllowed(t)) t.setEnabled(false);
        }
    }

    private int logCapChars() {
        int kb = (Integer) logCapSpinner.getValue();
        return kb * 1024;
    }

    // ─── Wiring ─────────────────────────────────────────────────────────

    private void wireActions(int fs) {
        fromMessageButton.addActionListener(e -> onFromMessage());
        fetchButton.addActionListener(e -> fetchBaseline());
        runButton.addActionListener(e -> startRun());
        pauseButton.addActionListener(e -> pauseRun());
        resumeButton.addActionListener(e -> resumeRun());
        stopButton.addActionListener(e -> stopRun());
        exportButton.addActionListener(e -> exportResults());
        resendButton.addActionListener(e -> resendSelected());
        copyUrlButton.addActionListener(e -> copySelectedUrl());
        copyCurlButton.addActionListener(e -> copySelectedCurl());
        clearResultsButton.addActionListener(e -> clearResults());
        pauseButton.setEnabled(false);
        resumeButton.setEnabled(false);
        stopButton.setEnabled(false);
        runButton.setEnabled(false);
        exportButton.setEnabled(false);
        resendButton.setEnabled(false);
        copyUrlButton.setEnabled(false);
        copyCurlButton.setEnabled(false);
        clearResultsButton.setEnabled(false);
        addHeaderButton.addActionListener(e -> addCustomHeaderRow());
        removeHeaderButton.addActionListener(e -> removeCustomHeaderRow());
        addFixedHeaderButton.addActionListener(e -> addFixedHeaderRow());
        removeFixedHeaderButton.addActionListener(e -> removeFixedHeaderRow());
        clearHeaderButton.addActionListener(e -> {
            customHeaderModel.clear();
            engine.clearCustomHeaders();
            appendLog("[*] Custom headers cleared.");
            saveHeaders();
        });
        addFuzzBodyButton.addActionListener(e -> markSelectionAsFuzz());
        formatBodyButton.addActionListener(e -> formatBodyEditor());
        loadBodyButton.addActionListener(e -> loadBodyFromBase());
        enableAllButton.addActionListener(e -> setAllEnabled(true));
        disableAllButton.addActionListener(e -> setAllEnabled(false));
        invertButton.addActionListener(e -> invertEnabled());
        addTechButton.addActionListener(e -> addCustomTechnique());
        editTechButton.addActionListener(e -> editCustomTechnique());
        removeTechButton.addActionListener(e -> removeCustomTechnique());
        duplicateTechButton.addActionListener(e -> duplicateCustomTechnique());

        fuzzModeBox.addActionListener(e -> {
            boolean on = fuzzModeBox.isSelected();
            fuzzWordlistField.setEnabled(on);
            fuzzBrowseButton.setEnabled(on);
            fuzzUrlBox.setEnabled(on);
            urlModeCombo.setEnabled(on);
            fuzzHeaderBox.setEnabled(on);
            fuzzBodyBox.setEnabled(on);
            customHeaderTable.setEnabled(on);
            addHeaderButton.setEnabled(on);
            removeHeaderButton.setEnabled(on);
            clearHeaderButton.setEnabled(on);
            bodyModeCombo.setEnabled(on);
            bodyTemplateEditor.setEnabled(on);
            formatBodyButton.setEnabled(on);
            addFuzzBodyButton.setEnabled(on);
            loadBodyButton.setEnabled(on);
            runButton.setEnabled(on || (countEnabledTechniques() > 0 && baseMsg != null));
        });
        fuzzBrowseButton.addActionListener(e -> {
            javax.swing.JFileChooser fc = new javax.swing.JFileChooser();
            fc.setDialogTitle("Select Wordlist");
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "Text files (*.txt, *.lst)", "txt", "lst"));
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "All files (*)", "*"));
            int result = fc.showOpenDialog(this);
            if (result == javax.swing.JFileChooser.APPROVE_OPTION) {
                fuzzWordlistField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, fs - 1));
        logArea.setBackground(BG_DARK);
        logArea.setForeground(FG);
        logArea.setCaretColor(FG);

        techniqueTable.getSelectionModel().addListSelectionListener(e -> {
            int row = techniqueTable.getSelectedRow();
            if (row >= 0) {
                editTechButton.setEnabled(true);
                removeTechButton.setEnabled(true);
                duplicateTechButton.setEnabled(true);
            } else {
                editTechButton.setEnabled(false);
                removeTechButton.setEnabled(false);
                duplicateTechButton.setEnabled(false);
            }
        });

        oauthDetectButton.addActionListener(e -> onOauthDetectUrl(oauthUrlField.getText()));
        oauthFromMessageButton.addActionListener(e -> onFromMessage());
        oauthAddParamButton.addActionListener(e -> oauthAddParam());
        oauthRemoveParamButton.addActionListener(e -> oauthRemoveParam());
        oauthRunButton.addActionListener(e -> runOauth());
        oauthStopButton.addActionListener(e -> stopOauth());
        oauthStopButton.setEnabled(false);
        oauthRunButton.setEnabled(false);
    }

    // ─── Public API for popup menu ──────────────────────────────────────

    public void setBaseMessage(HttpMessage msg) {
        if (msg == null) {
            System.err.println("[Hacktor] setBaseMessage: msg is null!");
            return;
        }
        try {
            String urlStr = msg.getRequestHeader().getURI().toString();
            baseMsg = msg.cloneAll();
            urlField.setText(urlStr);
            rebuildTechniques();
            baselineLabel.setText("Baseline: not fetched");
            baselineLabel.setForeground(FG_DIM);
            baselineStatus = -1;
            baselineLen = 0;
            runButton.setEnabled(true);
            appendLog("[*] Target set: " + urlStr);
            onOauthDetectMessage(msg);
        } catch (Exception ex) {
            System.err.println("[Hacktor] setBaseMessage EXCEPTION: " + ex.getMessage());
            appendLog("[!] setBaseMessage failed: " + ex.getMessage());
        }
    }

    // ─── Actions: target ────────────────────────────────────────────────

    private void onFromMessage() {
        try {
            org.parosproxy.paros.view.SiteMapPanel smp =
                org.parosproxy.paros.view.View.getSingleton().getSiteTreePanel();
            if (smp == null) return;
            javax.swing.JTree tree = smp.getTreeSite();
            if (tree == null) return;
            Object sel = tree.getLastSelectedPathComponent();
            if (sel instanceof org.parosproxy.paros.model.SiteNode) {
                org.parosproxy.paros.model.SiteNode siteNode =
                    (org.parosproxy.paros.model.SiteNode) sel;
                org.parosproxy.paros.model.HistoryReference href =
                    siteNode.getHistoryReference();
                if (href != null) {
                    HttpMessage msg = href.getHttpMessage();
                    if (msg != null) setBaseMessage(msg);
                }
            }
        } catch (Exception ex) {
            appendLog("[!] Could not read selected message: " + ex.getMessage());
        }
    }

    private void fetchBaseline() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            appendLog("[!] Enter a URL or select a message first.");
            return;
        }
        if (baseMsg == null) {
            try {
                if (!url.startsWith("http")) url = "https://" + url;
                org.apache.commons.httpclient.URI uri =
                    new org.apache.commons.httpclient.URI(url, true);
                baseMsg = new HttpMessage(uri);
                baseMsg.getRequestHeader().setHeader("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                baseMsg.getRequestHeader().setHeader("Accept", "*/*");
                baseMsg.getRequestHeader().setHeader("Accept-Language", "en-US,en;q=0.9");
            } catch (Exception e) {
                appendLog("[!] Invalid URL: " + e.getMessage());
                return;
            }
        }

        onOauthDetectUrl(url);

        HttpSender s = createSender();
        s.setFollowRedirect(followRedirectsBox.isSelected());
        try {
            for (HacktorEngine.CustomHeader ch : engine.getFixedHeaders()) {
                HacktorEngine.applyCustomHeader(baseMsg, ch);
            }
            s.sendAndReceive(baseMsg);
            baselineStatus = baseMsg.getResponseHeader().getStatusCode();
            baselineLen = baseMsg.getResponseBody().toString().length();
            boolean isErr = engine.looksLikeErrorPage(baselineStatus,
                baseMsg.getResponseBody().toString(), baselineLen, 0);
            baselineLabel.setText(String.format("Baseline: %d (%d bytes)%s",
                baselineStatus, baselineLen, isErr ? " - error page detected" : ""));
            baselineLabel.setForeground(
                baselineStatus >= 200 && baselineStatus < 400 ? GREEN : ORANGE);
            appendLog(String.format("[*] Baseline: %d (%d bytes)%s",
                baselineStatus, baselineLen, isErr ? " [error page]" : ""));
            rebuildTechniques();
            runButton.setEnabled(true);
        } catch (Exception e) {
            appendLog("[!] Baseline fetch failed: " + e.getMessage());
        } finally {
            s.shutdown();
        }
    }

    // ─── Actions: techniques ────────────────────────────────────────────

    private void rebuildTechniques() {
        try {
            // Snapshot the current enable state so toggles survive URL changes,
            // baseline fetches, and rebuilds. Both per-row choices and whole-family
            // switches are re-applied to the freshly generated techniques.
            Map<String, Boolean> snap = new LinkedHashMap<>();
            Map<String, Integer> famTotal = new LinkedHashMap<>();
            Map<String, Integer> famOn = new LinkedHashMap<>();
            for (Technique t : techniqueModel.getAll()) {
                snap.put(t.getFamily() + "\u0000" + t.getLabel(), t.isEnabled());
                famTotal.merge(t.getFamily(), 1, Integer::sum);
                if (t.isEnabled()) famOn.merge(t.getFamily(), 1, Integer::sum);
            }

            HttpMessage src = baseMsg != null ? baseMsg : syntheticBaselineMessage();
            List<Technique> customs = techniqueModel.getAll().stream()
                .filter(Technique::isCustom).collect(Collectors.toList());
            List<Technique> techs = new ArrayList<>(engine.buildTechniques(src));
            if (!customs.isEmpty()) {
                techs.addAll(customs);
                appendLog("[*] Kept " + customs.size() + " custom technique(s).");
            }
            techniqueModel.setRows(techs);

            // Re-apply session toggles first, then persisted preferences for any
            // technique the session has not explicitly touched this run.
            for (Technique t : techs) {
                String key = t.getFamily() + "\u0000" + t.getLabel();
                Boolean prev = snap.get(key);
                boolean famFullyOff = famTotal.getOrDefault(t.getFamily(), 0) > 0
                    && famOn.getOrDefault(t.getFamily(), 0) == 0;
                if (prev != null) {
                    t.setEnabled(prev);
                } else if (famFullyOff) {
                    t.setEnabled(false);
                } else if (persistedRowsOff.contains(key)) {
                    t.setEnabled(false);
                } else if (persistedRowsOn.contains(key)) {
                    t.setEnabled(true);
                } else if (Boolean.FALSE.equals(persistedFamilyOn.get(t.getFamily()))) {
                    t.setEnabled(false);
                } else if (Boolean.TRUE.equals(persistedFamilyOn.get(t.getFamily()))) {
                    t.setEnabled(true);
                }
            }

            applyTierGate(techs);
            applyTechniqueFilter();
            rebuildFamilyBoxes();
            updateCounts();
            syncFamilyBoxes();
            appendLog("[*] Generated " + techs.size() + " bypass techniques"
                + (baseMsg == null
                    ? " (placeholder set \u2014 pick a target to run them)"
                    : ""));
        } catch (Exception ex) {
            appendLog("[!] rebuildTechniques failed: " + ex.getMessage());
        }
    }

    private HttpMessage syntheticBaselineMessage() {
        try {
            return new HttpMessage(new org.apache.commons.httpclient.URI(
                "http://example.com/?u=a&p=b", true));
        } catch (Exception e) {
            return new HttpMessage();
        }
    }

    private void rebuildFamilyBoxes() {
        familyPanel.removeAll();
        familyBoxes.clear();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Technique t : techniqueModel.getAll()) {
            counts.merge(t.getFamily(), 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            JCheckBox cb = new JCheckBox(e.getKey() + " (" + e.getValue() + ")", true);
            cb.setFont(cb.getFont().deriveFont(Font.PLAIN, 10f));
            cb.setBackground(BG);
            cb.setForeground(FG);
            cb.setToolTipText("Toggle all " + e.getKey() + " techniques");
            String family = e.getKey();
            cb.addActionListener(ev -> {
                boolean on = cb.isSelected();
                for (Technique t : techniqueModel.getAll()) {
                    if (t.getFamily().equals(family)) t.setEnabled(on);
                }
                techniqueModel.fireTableDataChanged();
                afterTechniqueToggle();
            });
            familyBoxes.put(e.getKey(), cb);
            familyPanel.add(cb);
        }
        familyPanel.revalidate();
        familyPanel.repaint();
    }

    private void syncFamilyBoxes() {
        List<Technique> all = techniqueModel.getAll();
        Map<String, long[]> counts = new LinkedHashMap<>();
        for (Technique t : all) {
            counts.computeIfAbsent(t.getFamily(), k -> new long[2])[0]++;
            if (t.isEnabled()) counts.get(t.getFamily())[1]++;
        }
        for (Map.Entry<String, JCheckBox> entry : familyBoxes.entrySet()) {
            String family = entry.getKey();
            JCheckBox cb = entry.getValue();
            long[] c = counts.getOrDefault(family, new long[2]);
            cb.setSelected(c[1] == c[0] && c[0] > 0);
            cb.setText(family + " (" + c[1] + ")");
        }
    }

    /** Refresh the enabled-count label of the family boxes without touching their
     *  selection. Individual technique toggles must never change the family box
     *  state; the family boxes only check/uncheck a whole family when clicked
     *  directly. */
    private void refreshFamilyCounts() {
        List<Technique> all = techniqueModel.getAll();
        Map<String, long[]> counts = new LinkedHashMap<>();
        for (Technique t : all) {
            counts.computeIfAbsent(t.getFamily(), k -> new long[2])[0]++;
            if (t.isEnabled()) counts.get(t.getFamily())[1]++;
        }
        for (Map.Entry<String, JCheckBox> entry : familyBoxes.entrySet()) {
            String family = entry.getKey();
            long[] c = counts.getOrDefault(family, new long[2]);
            entry.getValue().setText(family + " (" + c[1] + ")");
        }
    }

    /** Toggles a single technique (mouse or keyboard) without disturbing the family
     *  checkbox state. */
    private void toggleTechnique(int row) {
        Technique t = techniqueModel.getAt(row);
        if (t == null) return;
        t.setEnabled(!t.isEnabled());
        techniqueModel.fireTableRowsUpdated(row, row);
        afterTechniqueToggle();
    }

    /** Bookkeeping shared by every per-technique toggle path. */
    private void afterTechniqueToggle() {
        updateCounts();
        refreshFamilyCounts();
        saveFamilies();
    }

    private void setAllEnabled(boolean enabled) {
        for (Technique t : techniqueModel.getAll()) t.setEnabled(enabled);
        techniqueModel.fireTableDataChanged();
        updateCounts();
        for (JCheckBox cb : familyBoxes.values()) cb.setSelected(enabled);
        saveFamilies();
    }

    private void invertEnabled() {
        for (Technique t : techniqueModel.getAll()) t.setEnabled(!t.isEnabled());
        techniqueModel.fireTableDataChanged();
        updateCounts();
        syncFamilyBoxes();
        appendLog("[*] Inverted technique enable state.");
        saveFamilies();
    }

    private void updateCounts() {
        long enabled = 0;
        long total = 0;
        for (Technique t : techniqueModel.getAll()) {
            total++;
            if (t.isEnabled()) enabled++;
        }
        techniqueSummary.setText(enabled + " / " + total + " techniques enabled");
        runButton.setEnabled((enabled > 0 || fuzzModeBox.isSelected()) && baseMsg != null);
    }

    private static boolean matchesColumn(Technique t, String col, String q) {
        switch (col) {
            case "Label": return t.getLabel().toLowerCase().contains(q);
            case "Family": return t.getFamily().toLowerCase().contains(q);
            case "Description": return t.getDescription().toLowerCase().contains(q);
            default:
                return t.getLabel().toLowerCase().contains(q)
                    || t.getFamily().toLowerCase().contains(q)
                    || t.getDescription().toLowerCase().contains(q);
        }
    }

    private void applyTechniqueFilter() {
        String q = filterField.getText().trim().toLowerCase();
        String col = (String) filterColumnCombo.getSelectedItem();
        if (col == null) col = "All";
        final String colF = col;
        String vulnType = (String) vulnTypeCombo.getSelectedItem();
        Predicate<Technique> p = t -> true;
        if (showCustomOnlyBox.isSelected()) p = p.and(Technique::isCustom);
        if (vulnType != null && !"All Types".equals(vulnType)) {
            p = p.and(t -> t.getFamily().equalsIgnoreCase(vulnType));
        }
        if (!q.isEmpty()) p = p.and(t -> matchesColumn(t, colF, q));
        techniqueModel.setFilter(p);
    }

    // ─── Persistence: settings / families / headers ────────────────────

    private static org.apache.commons.configuration.FileConfiguration hacktorCfg() {
        try {
            return Model.getSingleton().getOptionsParam().getConfig();
        } catch (Exception ex) {
            return null;
        }
    }

    private static String cfgStr(String key, String def) {
        try {
            org.apache.commons.configuration.Configuration c =
                Model.getSingleton().getOptionsParam().getConfig();
            if (c == null) return def;
            return c.getString(key, def);
        } catch (Exception ex) {
            return def;
        }
    }

    private static int cfgInt(String key, int def) {
        try {
            org.apache.commons.configuration.Configuration c =
                Model.getSingleton().getOptionsParam().getConfig();
            if (c == null) return def;
            return c.getInt(key, def);
        } catch (Exception ex) {
            return def;
        }
    }

    private static String esc(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String unesc(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case '\\': sb.append('\\'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    default:   sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Saves all general-run settings and spinners to ZAP config. */
    private void saveSettings() {
        try {
            org.apache.commons.configuration.FileConfiguration cfg = hacktorCfg();
            if (cfg == null) return;
            StringBuilder sb = new StringBuilder();
            sb.append("followRedirects=").append(followRedirectsBox.isSelected()).append('\n');
            sb.append("suppressErrors=").append(suppressErrorsBox.isSelected()).append('\n');
            sb.append("stopOnCandidate=").append(stopOnCandidateBox.isSelected()).append('\n');
            sb.append("retryOnError=").append(retryOnErrorBox.isSelected()).append('\n');
            sb.append("useRawWire=").append(useRawWireBox.isSelected()).append('\n');
            sb.append("backoff=").append(backoffBox.isSelected()).append('\n');
            sb.append("fuzzMode=").append(fuzzModeBox.isSelected()).append('\n');
            sb.append("fuzzUrl=").append(fuzzUrlBox.isSelected()).append('\n');
            sb.append("urlMode=").append(urlModeCombo.getSelectedIndex()).append('\n');
            sb.append("fuzzHeader=").append(fuzzHeaderBox.isSelected()).append('\n');
            sb.append("fuzzBody=").append(fuzzBodyBox.isSelected()).append('\n');
            sb.append("classicTier=").append(classicTierBox.isSelected()).append('\n');
            sb.append("rareTier=").append(rareTierBox.isSelected()).append('\n');
            sb.append("novelTier=").append(novelTierBox.isSelected()).append('\n');
            sb.append("oauthClassic=").append(oauthClassicBox.isSelected()).append('\n');
            sb.append("oauthRare=").append(oauthRareBox.isSelected()).append('\n');
            sb.append("oauthNovel=").append(oauthNovelBox.isSelected()).append('\n');
            sb.append("showCustomOnly=").append(showCustomOnlyBox.isSelected()).append('\n');
            sb.append("candidatesOnly=").append(candidatesOnlyBox.isSelected()).append('\n');
            sb.append("errorsOnly=").append(errorsOnlyBox.isSelected()).append('\n');
            sb.append("rateLimit=").append(rateLimitSpinner.getValue()).append('\n');
            sb.append("threads=").append(threadsSpinner.getValue()).append('\n');
            sb.append("timeout=").append(timeoutSpinner.getValue()).append('\n');
            sb.append("maxProbes=").append(maxProbesSpinner.getValue()).append('\n');
            sb.append("maxResults=").append(maxResultsSpinner.getValue()).append('\n');
            sb.append("logCap=").append(logCapSpinner.getValue()).append('\n');
            sb.append("filterCol=").append(filterColumnCombo.getSelectedIndex()).append('\n');
            sb.append("vulnType=").append(vulnTypeCombo.getSelectedIndex()).append('\n');
            sb.append("bodyMode=").append(bodyModeCombo.getSelectedIndex()).append('\n');
            sb.append("wordlist=").append(esc(fuzzWordlistField.getText().trim())).append('\n');
            cfg.setProperty("hacktor.settings", sb.toString());
            try { cfg.save(); } catch (Exception ignored) {}
        } catch (Exception ignored) {}
    }

    /** Restores controls from persisted config. Must run before any listeners that save. */
    private void loadSettings() {
        try {
            String raw = cfgStr("hacktor.settings", null);
            if (raw == null) return;
            Map<String, String> m = new LinkedHashMap<>();
            for (String line : raw.split("\n")) {
                int eq = line.indexOf('=');
                if (eq > 0) m.put(line.substring(0, eq), line.substring(eq + 1));
            }
            setIf(m, "followRedirects", b -> followRedirectsBox.setSelected(b));
            setIf(m, "suppressErrors",  b -> suppressErrorsBox.setSelected(b));
            setIf(m, "stopOnCandidate", b -> stopOnCandidateBox.setSelected(b));
            setIf(m, "retryOnError",    b -> retryOnErrorBox.setSelected(b));
            setIf(m, "useRawWire",      b -> useRawWireBox.setSelected(b));
            setIf(m, "backoff",         b -> backoffBox.setSelected(b));
            setIf(m, "fuzzMode",        b -> fuzzModeBox.setSelected(b));
            setIf(m, "fuzzUrl",         b -> fuzzUrlBox.setSelected(b));
            setIdx(m, "urlMode",        urlModeCombo, 0, 2);
            setIf(m, "fuzzHeader",      b -> fuzzHeaderBox.setSelected(b));
            setIf(m, "fuzzBody",        b -> fuzzBodyBox.setSelected(b));
            setIf(m, "classicTier",     b -> classicTierBox.setSelected(b));
            setIf(m, "rareTier",        b -> rareTierBox.setSelected(b));
            setIf(m, "novelTier",       b -> novelTierBox.setSelected(b));
            setIf(m, "oauthClassic",    b -> oauthClassicBox.setSelected(b));
            setIf(m, "oauthRare",       b -> oauthRareBox.setSelected(b));
            setIf(m, "oauthNovel",      b -> oauthNovelBox.setSelected(b));
            setIf(m, "showCustomOnly",  b -> showCustomOnlyBox.setSelected(b));
            setIf(m, "candidatesOnly",  b -> candidatesOnlyBox.setSelected(b));
            setIf(m, "errorsOnly",      b -> errorsOnlyBox.setSelected(b));
            setIdx(m, "rateLimit", rateLimitSpinner, 0, 10000);
            setIdx(m, "threads",   threadsSpinner,   1, 16);
            setIdx(m, "timeout",   timeoutSpinner,   1, 120);
            setIdx(m, "maxProbes", maxProbesSpinner, 0, 10000);
            setIdx(m, "maxResults",maxResultsSpinner,1000, 200000);
            setIdx(m, "logCap",    logCapSpinner,    25, 10000);
            setIdx(m, "filterCol", filterColumnCombo, 0, filterColumnCombo.getItemCount() - 1);
            setIdx(m, "vulnType",  vulnTypeCombo,    0, vulnTypeCombo.getItemCount() - 1);
            setIdx(m, "bodyMode",  bodyModeCombo,    0, bodyModeCombo.getItemCount() - 1);
            if (m.containsKey("wordlist")) fuzzWordlistField.setText(unesc(m.get("wordlist")));
        } catch (Exception ignored) {}
    }

    private static void setIf(Map<String, String> m, String k, java.util.function.Consumer<Boolean> s) {
        if (!m.containsKey(k)) return;
        s.accept(Boolean.parseBoolean(m.get(k)));
    }

    private static void setIdx(Map<String, String> m, String k, JSpinner sp, int lo, int hi) {
        if (!m.containsKey(k)) return;
        try { int v = Integer.parseInt(m.get(k)); sp.setValue(Math.min(hi, Math.max(lo, v))); }
        catch (Exception ignored) {}
    }

    private static void setIdx(Map<String, String> m, String k, JComboBox<?> cb, int lo, int hi) {
        if (!m.containsKey(k)) return;
        try { int v = Integer.parseInt(m.get(k)); cb.setSelectedIndex(Math.min(hi, Math.max(lo, v))); }
        catch (Exception ignored) {}
    }

    /** Persist the current family/row enable state so it survives restarts and rebuilds. */
    private void saveFamilies() {
        try {
            org.apache.commons.configuration.FileConfiguration cfg = hacktorCfg();
            if (cfg == null) return;
            persistedFamilyOn.clear();
            Set<String> allOn = new LinkedHashSet<>();
            Set<String> allOff = new LinkedHashSet<>();
            Set<String> rowOn = new LinkedHashSet<>();
            Set<String> rowOff = new LinkedHashSet<>();
            Map<String, Integer> famTotal = new LinkedHashMap<>();
            Map<String, Integer> famCnt = new LinkedHashMap<>();
            for (Technique t : techniqueModel.getAll()) {
                famTotal.merge(t.getFamily(), 1, Integer::sum);
                if (t.isEnabled()) famCnt.merge(t.getFamily(), 1, Integer::sum);
            }
            for (Map.Entry<String, Integer> e : famTotal.entrySet()) {
                String fam = e.getKey();
                int on = famCnt.getOrDefault(fam, 0);
                int tot = e.getValue();
                if (on == 0) allOff.add(fam);
                else        allOn.add(fam);
                boolean mixed = on > 0 && on < tot;
                if (mixed) {
                    for (Technique t : techniqueModel.getAll()) {
                        if (!t.getFamily().equals(fam)) continue;
                        String key = fam + "\u0000" + t.getLabel();
                        if (t.isEnabled()) rowOn.add(key);
                        else               rowOff.add(key);
                    }
                }
            }
            persistedFamilyOn.clear();
            for (String f : allOn)  persistedFamilyOn.put(f, Boolean.TRUE);
            for (String f : allOff) persistedFamilyOn.put(f, Boolean.FALSE);
            persistedRowsOn.clear();
            persistedRowsOn.addAll(rowOn);
            persistedRowsOff.clear();
            persistedRowsOff.addAll(rowOff);
            cfg.setProperty("hacktor.famOn",  String.join("\n", allOn));
            cfg.setProperty("hacktor.famOff", String.join("\n", allOff));
            cfg.setProperty("hacktor.rowsOn", String.join("\n", rowOn));
            cfg.setProperty("hacktor.rowsOff", String.join("\n", rowOff));
            try { cfg.save(); } catch (Exception ignored) {}
        } catch (Exception ignored) {}
    }

    private void loadFamiliesFromConfig() {
        try {
            String on  = cfgStr("hacktor.famOn",  "");
            String off = cfgStr("hacktor.famOff", "");
            persistedFamilyOn.clear();
            for (String f : on.split("\n"))  { f = f.trim(); if (!f.isEmpty()) persistedFamilyOn.put(f, Boolean.TRUE); }
            for (String f : off.split("\n")) { f = f.trim(); if (!f.isEmpty()) persistedFamilyOn.put(f, Boolean.FALSE); }
            String ron  = cfgStr("hacktor.rowsOn",  "");
            String roff = cfgStr("hacktor.rowsOff", "");
            persistedRowsOn.clear();
            persistedRowsOff.clear();
            for (String l : ron.split("\n"))  { l = l.trim(); if (!l.isEmpty()) persistedRowsOn.add(l); }
            for (String l : roff.split("\n")) { l = l.trim(); if (!l.isEmpty()) persistedRowsOff.add(l); }
        } catch (Exception ignored) {}
    }

    /** Persists current custom-header rules so they survive ZAP restarts. */
    private void saveHeaders() {
        try {
            org.apache.commons.configuration.FileConfiguration cfg = hacktorCfg();
            if (cfg == null) return;
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (HacktorEngine.CustomHeader ch : customHeaderModel.getRules()) {
                if (!first) sb.append('\n');
                sb.append(esc(ch.getName()))
                  .append('\t')
                  .append(esc(ch.getFind()))
                  .append('\t')
                  .append(ch.getMode().name());
                first = false;
            }
            cfg.setProperty("hacktor.headers", sb.toString());
            try { cfg.save(); } catch (Exception ignored) {}
        } catch (Exception ignored) {}
    }

    private void loadHeadersFromConfig() {
        try {
            String raw = cfgStr("hacktor.headers", "");
            if (raw.isEmpty()) return;
            for (String line : raw.split("\n")) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split("\t", 3);
                if (parts.length < 3) continue;
                String name = unesc(parts[0]);
                String find = unesc(parts[1]);
                HacktorEngine.HeaderMode mode;
                try { mode = HacktorEngine.HeaderMode.valueOf(parts[2].trim()); }
                catch (Exception ex) { mode = HacktorEngine.HeaderMode.SET; }
                HacktorEngine.CustomHeader ch = new HacktorEngine.CustomHeader(
                    name, new ArrayList<>(), mode);
                ch.setFind(find);
                customHeaderModel.addRule(ch);
            }
        } catch (Exception ignored) {}
    }

    private void saveFixedHeaders() {
        try {
            org.apache.commons.configuration.FileConfiguration cfg = hacktorCfg();
            if (cfg == null) return;
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (HacktorEngine.CustomHeader h : fixedHeaderModel.getFixedHeaders()) {
                if (!first) sb.append('\n');
                sb.append(esc(h.getName())).append('\t')
                  .append(esc(h.getValues().isEmpty() ? "" : String.join(", ", h.getValues())));
                first = false;
            }
            cfg.setProperty("hacktor.fixedheaders", sb.toString());
            try { cfg.save(); } catch (Exception ignored) {}
        } catch (Exception ignored) {}
    }

    private void loadFixedHeadersFromConfig() {
        try {
            String raw = cfgStr("hacktor.fixedheaders", "");
            if (raw.isEmpty()) return;
            for (String line : raw.split("\n")) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split("\t", 2);
                if (parts.length < 2) continue;
                List<String> vals = new ArrayList<>();
                vals.add(unesc(parts[1]));
                HacktorEngine.CustomHeader h = new HacktorEngine.CustomHeader(
                    unesc(parts[0]), vals, HacktorEngine.HeaderMode.SET);
                fixedHeaderModel.addRow(h);
            }
        } catch (Exception ignored) {}
    }

    /** One-time startup: load persisted config and wire save-listeners. */
    private void initPersistence() {
        loadSettings();
        loadFamiliesFromConfig();
        loadHeadersFromConfig();
        loadFixedHeadersFromConfig();
        syncFixedHeadersToEngine();
        engine.setForceRawWire(useRawWireBox.isSelected());

        for (JCheckBox cb : new JCheckBox[]{
                followRedirectsBox, suppressErrorsBox, stopOnCandidateBox,
                retryOnErrorBox, useRawWireBox, backoffBox, fuzzModeBox, fuzzUrlBox,
                fuzzHeaderBox, fuzzBodyBox, classicTierBox, rareTierBox,
                novelTierBox, oauthClassicBox, oauthRareBox, oauthNovelBox,
                showCustomOnlyBox, candidatesOnlyBox, errorsOnlyBox}) {
            cb.addItemListener(e -> saveSettings());
        }
        for (JSpinner sp : new JSpinner[]{
                rateLimitSpinner, threadsSpinner, timeoutSpinner,
                maxProbesSpinner, maxResultsSpinner, logCapSpinner}) {
            sp.addChangeListener(e -> saveSettings());
        }
        for (JComboBox<?> cm : new JComboBox<?>[]{
                filterColumnCombo, vulnTypeCombo, bodyModeCombo, urlModeCombo}) {
            cm.addItemListener(e -> saveSettings());
        }
        fuzzWordlistField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { saveSettings(); }
            public void removeUpdate(DocumentEvent e)  { saveSettings(); }
            public void changedUpdate(DocumentEvent e)  { saveSettings(); }
        });
    }

    // ─── Custom technique CRUD ──────────────────────────────────────────

    private void addCustomTechnique() {
        Window owner = SwingUtilities.getWindowAncestor(this);
        CustomTechDialog d = new CustomTechDialog(owner, "Add Custom Technique", null);
        d.setVisible(true);
        if (d.isConfirmed()) {
            Technique t = d.buildTechnique();
            if (t != null) {
                techniqueModel.addCustom(t);
                rebuildFamilyBoxes();
                updateCounts();
                appendLog("[+] Added custom technique: " + t.getLabel());
            }
        }
    }

    private void editCustomTechnique() {
        int row = techniqueTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = techniqueTable.convertRowIndexToModel(row);
        Technique t = techniqueModel.getAt(modelRow);
        if (t == null) return;
        Window owner = SwingUtilities.getWindowAncestor(this);
        if (!t.isCustom()) {
            int confirm = JOptionPane.showConfirmDialog(this,
                "Built-in techniques run a compiled mutation and can't be edited directly.\n"
                + "Convert \"" + t.getLabel() + "\" into an editable custom technique?",
                "Convert to Editable", JOptionPane.OK_CANCEL_OPTION);
            if (confirm != JOptionPane.OK_OPTION) return;
            CustomTechDialog d = new CustomTechDialog(owner, "Edit Technique (editable copy)", t);
            d.setVisible(true);
            if (d.isConfirmed()) {
                Technique converted = d.buildTechnique();
                if (converted == null) {
                    appendLog("[!] Conversion cancelled: fill in the mutation fields "
                        + "(path / header / payload) first.");
                    return;
                }
                techniqueModel.removeCustom(t);
                techniqueModel.addCustom(converted);
                rebuildFamilyBoxes();
                updateCounts();
                appendLog("[~] Converted to editable custom technique: " + converted.getLabel());
            }
            return;
        }
        CustomTechDialog d = new CustomTechDialog(owner, "Edit Custom Technique", t);
        d.setVisible(true);
        if (d.isConfirmed()) {
            d.applyTo(t);
            techniqueModel.fireTableDataChanged();
            rebuildFamilyBoxes();
            updateCounts();
            appendLog("[~] Edited custom technique: " + t.getLabel());
        }
    }

    private void removeCustomTechnique() {
        int row = techniqueTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = techniqueTable.convertRowIndexToModel(row);
        Technique t = techniqueModel.getAt(modelRow);
        if (t == null) return;
        int confirm = JOptionPane.showConfirmDialog(this,
            "Remove technique \"" + t.getLabel() + "\""
                + (t.isCustom() ? "" : " (built-in; a Rebuild re-generates it)") + "?",
            "Confirm Remove", JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            techniqueModel.removeCustom(t);
            rebuildFamilyBoxes();
            updateCounts();
            appendLog("[-] Removed " + (t.isCustom() ? "custom" : "built-in")
                + " technique: " + t.getLabel());
        }
    }

    private void duplicateCustomTechnique() {
        int row = techniqueTable.getSelectedRow();
        if (row < 0) return;
        int modelRow = techniqueTable.convertRowIndexToModel(row);
        Technique t = techniqueModel.getAt(modelRow);
        if (t == null) return;
        Technique copy = t.copy(t.getLabel() + " (copy)");
        copy.setEnabled(t.isEnabled());
        techniqueModel.addCustom(copy);
        rebuildFamilyBoxes();
        updateCounts();
        appendLog("[+] Duplicated " + (t.isCustom() ? "custom" : "built-in")
            + " technique: " + copy.getLabel());
    }

    // ─── Actions: custom headers ────────────────────────────────────────

    private void addCustomHeaderRow() {
        JTextField nameField = new JTextField();
        JTextField findField = new JTextField();
        JComboBox<String> modeCombo = new JComboBox<>(new String[]{"SET", "APPEND", "PREPEND"});
        modeCombo.setSelectedItem("APPEND");
        JPanel form = new JPanel(new GridLayout(0, 1, 4, 6));
        form.add(styledPair(new JLabel("Header name:"), nameField));
        form.add(styledPair(new JLabel("Find (replaced by each word; blank = FUZZ):"), findField));
        form.add(styledPair(new JLabel("Mode:"), modeCombo));
        int ok = JOptionPane.showConfirmDialog(this, form,
            "Add Header Rule", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        String name = nameField.getText().trim();
        String find = findField.getText().trim();
        if (name.isEmpty()) {
            appendLog("[!] Header name is required.");
            return;
        }
        HacktorEngine.HeaderMode m;
        try {
            m = HacktorEngine.HeaderMode.valueOf(modeCombo.getSelectedItem().toString());
        } catch (Exception ex) {
            m = HacktorEngine.HeaderMode.SET;
        }
        HacktorEngine.CustomHeader h = new HacktorEngine.CustomHeader(name, new ArrayList<>(), m);
        h.setFind(find);
        customHeaderModel.addRule(h);
        saveHeaders();
        appendLog("[+] Custom header: " + m + " " + name
            + (find.isEmpty() ? " (FUZZ fallback)" : " find=" + find));
    }

    private void removeCustomHeaderRow() {
        int row = customHeaderTable.getSelectedRow();
        if (row < 0) {
            appendLog("[!] Select a header rule to remove.");
            return;
        }
        int modelRow = customHeaderTable.convertRowIndexToModel(row);
        HacktorEngine.CustomHeader h = customHeaderModel.getAt(modelRow);
        if (h == null) return;
        customHeaderModel.removeAt(modelRow);
        saveHeaders();
        appendLog("[-] Removed custom header: " + h.getName());
    }

    // ─── Actions: fixed request headers ─────────────────────────────────

    private void addFixedHeaderRow() {
        JTextField nameField = new JTextField();
        JTextField valueField = new JTextField();
        JPanel form = new JPanel(new GridLayout(0, 1, 4, 6));
        form.add(styledPair(new JLabel("Header name:"), nameField));
        form.add(styledPair(new JLabel("Value:"), valueField));
        int ok = JOptionPane.showConfirmDialog(this, form,
            "Add Fixed Header", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        String name = nameField.getText().trim();
        String value = valueField.getText();
        if (name.isEmpty()) {
            appendLog("[!] Header name is required.");
            return;
        }
        List<String> vals = new ArrayList<>();
        vals.add(value);
        HacktorEngine.CustomHeader h = new HacktorEngine.CustomHeader(
            name, vals, HacktorEngine.HeaderMode.SET);
        fixedHeaderModel.addRow(h);
        syncFixedHeadersToEngine();
        saveFixedHeaders();
        appendLog("[+] Fixed header: " + name + ": " + value);
    }

    private void removeFixedHeaderRow() {
        int row = fixedHeaderTable.getSelectedRow();
        if (row < 0) {
            appendLog("[!] Select a fixed header to remove.");
            return;
        }
        int modelRow = fixedHeaderTable.convertRowIndexToModel(row);
        HacktorEngine.CustomHeader h = fixedHeaderModel.getAt(modelRow);
        if (h == null) return;
        fixedHeaderModel.removeAt(modelRow);
        syncFixedHeadersToEngine();
        saveFixedHeaders();
        appendLog("[-] Removed fixed header: " + h.getName());
    }

    private void syncFixedHeadersToEngine() {
        engine.setFixedHeaders(fixedHeaderModel.getFixedHeaders());
    }

    // ─── Actions: body fuzz editor ──────────────────────────────────────

    private void markSelectionAsFuzz() {
        int start = bodyTemplateEditor.getSelectionStart();
        int end = bodyTemplateEditor.getSelectionEnd();
        if (start == end) {
            appendLog("[!] Select text in the body editor first, then press 'Add FUZZ'.");
            return;
        }
        bodyTemplateEditor.replaceRange("FUZZ", start, end);
        appendLog("[+] Selection replaced with FUZZ.");
    }

    private void formatBodyEditor() {
        String text = bodyTemplateEditor.getText();
        if (text == null || text.trim().isEmpty()) return;
        String formatted = prettyPrint(text);
        if (formatted == null) {
            appendLog("[!] Could not parse body (expected JSON/XML/HTML).");
            return;
        }
        bodyTemplateEditor.setText(formatted);
    }

    private void loadBodyFromBase() {
        if (baseMsg == null) {
            appendLog("[!] Fetch a baseline request first, or the body can be typed manually.");
            return;
        }
        String body = baseMsg.getRequestBody().toString();
        bodyTemplateEditor.setText(body);
        bodyTemplateEditor.setCaretPosition(0);
        appendLog("[*] Loaded body from base request.");
    }

    // ─── Actions: results ───────────────────────────────────────────────

    private void applyResultsFilter() {
        String q = resultsFilterField.getText().trim().toLowerCase();
        boolean cand = candidatesOnlyBox.isSelected();
        boolean errs = errorsOnlyBox.isSelected();
        Predicate<Result> p = r -> true;
        if (cand) p = p.and(r -> r.getVerdict() == Technique.Verdict.CANDIDATE);
        if (errs) p = p.and(r -> liveStatus(r) >= 400);
        String filter = q;
        if (!filter.isEmpty()) {
            p = p.and(r -> (r.getLabel() + " " + r.getFamily() + " " + r.getPath() + " "
                + r.getVerdict()).toLowerCase().contains(filter));
        }
        resultsModel.setFilter(p);
    }

    private int liveStatus(Result r) {
        HttpMessage m = r.getMessage();
        return m == null ? r.getStatus() : m.getResponseHeader().getStatusCode();
    }

    private void showSelectedResult() {
        Result r = getSelectedResult();
        boolean has = r != null && r.getMessage() != null;
        resendButton.setEnabled(has);
        copyUrlButton.setEnabled(r != null);
        copyCurlButton.setEnabled(has);
        if (r == null) {
            requestViewer.clearView();
            responseViewer.clearView();
            return;
        }
        HttpMessage m = r.getMessage();
        if (m == null) {
            requestViewer.clearView();
            responseViewer.clearView();
            return;
        }
        requestViewer.setMessage(m, true);
        responseViewer.setMessage(m, true);
    }

    private Result getSelectedResult() {
        int row = resultsTable.getSelectedRow();
        if (row < 0) return null;
        return resultsModel.getAt(row);
    }

    private void resendSelected() {
        Result r = getSelectedResult();
        if (r == null || r.getMessage() == null) {
            appendLog("[!] Select a result row with a message to resend.");
            return;
        }
        HttpMessage m = r.getMessage();
        HttpSender s = createSender();
        s.setFollowRedirect(followRedirectsBox.isSelected());
        try {
            int so = (Integer) timeoutSpinner.getValue();
            if (so > 0) {
                org.zaproxy.zap.network.HttpRequestConfig cfg = org.zaproxy.zap.network.HttpRequestConfig.builder()
                    .setSoTimeout(so * 1000).build();
                s.sendAndReceive(m, cfg);
            } else {
                s.sendAndReceive(m);
            }
            resultsModel.fireTableDataChanged();
            showSelectedResult();
            appendLog("[*] Resent: " + r.getLabel() + " -> HTTP "
                + m.getResponseHeader().getStatusCode());
        } catch (Exception e) {
            appendLog("[!] Resend failed: " + e.getMessage());
        } finally {
            s.shutdown();
        }
    }

    private void copySelectedUrl() {
        Result r = getSelectedResult();
        if (r == null) {
            appendLog("[!] Select a result row first.");
            return;
        }
        copyToClipboard(r.getPath());
        appendLog("[*] Copied path/URL: " + r.getPath());
    }

    private void copySelectedCurl() {
        Result r = getSelectedResult();
        if (r == null || r.getMessage() == null) {
            appendLog("[!] Select a result row first.");
            return;
        }
        String curl = buildCurl(r.getMessage());
        if (curl == null) {
            appendLog("[!] Could not build curl command for this message.");
            return;
        }
        copyToClipboard(curl);
        appendLog("[*] Copied curl command.");
    }

    private void clearResults() {
        resultsModel.clear();
        summaryLabel.setText("Ready");
        requestViewer.clearView();
        responseViewer.clearView();
        updateCounts();
        appendLog("[*] Results cleared.");
    }

    private void exportResults() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("hacktor-results.csv"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(fc.getSelectedFile()))) {
                pw.println("Category,Technique,Path,Status,Length,Baseline,Verdict,ReqMs,ResMs");
                for (Result r : resultsModel.getResults()) {
                    pw.printf("\"%s\",\"%s\",\"%s\",%d,%d,%d,\"%s\",%d,%d%n",
                        csvEscape(r.getFamily()), csvEscape(r.getLabel()),
                        csvEscape(r.getPath()),
                        liveStatus(r), liveLength(r), r.getBaselineStatus(),
                        r.getVerdict(), r.getReqTime(), r.getResTime());
                }
                appendLog("[*] Exported " + resultsModel.getRowCount() + " results");
            } catch (Exception e) {
                appendLog("[!] Export failed: " + e.getMessage());
            }
        }
    }

    // ─── Run / Stop / Pause / Resume ───────────────────────────────────

    private void startRun() {
        if (baseMsg == null) {
            String url = urlField.getText().trim();
            if (url.isEmpty()) {
                appendLog("[!] Enter a URL or select a message first.");
                return;
            }
            try {
                if (!url.startsWith("http")) url = "https://" + url;
                org.apache.commons.httpclient.URI uri =
                    new org.apache.commons.httpclient.URI(url, true);
                baseMsg = new HttpMessage(uri);
                baseMsg.getRequestHeader().setHeader("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                baseMsg.getRequestHeader().setHeader("Accept", "*/*");
                baseMsg.getRequestHeader().setHeader("Accept-Language", "en-US,en;q=0.9");
            } catch (Exception e) {
                appendLog("[!] Invalid URL: " + e.getMessage());
                return;
            }
        }
        if (fuzzModeBox.isSelected()) {
            String wl = fuzzWordlistField.getText().trim();
            if (wl.isEmpty()) {
                appendLog("[!] Select a wordlist file first.");
                return;
            }
            java.io.File wlFile = new java.io.File(wl);
            if (!wlFile.isFile()) {
                appendLog("[!] Wordlist file not found: " + wl);
                return;
            }
            boolean fuzzUrl = fuzzUrlBox.isSelected();
            boolean fuzzHdr = fuzzHeaderBox.isSelected();
            boolean fuzzBody = fuzzBodyBox.isSelected();
            if (!fuzzUrl && !fuzzHdr && !fuzzBody) {
                appendLog("[!] Select at least one fuzz target type (URL, Headers, or Body).");
                return;
            }
            if (fuzzUrl && !urlField.getText().trim().toUpperCase().contains("FUZZ")) {
                appendLog("[!] URL fuzzing is selected, but the URL has no FUZZ token.");
                return;
            }
            if (fuzzHdr && customHeaderModel.getRules().isEmpty()) {
                appendLog("[!] Header fuzzing is selected, but no header rules are defined.");
                return;
            }
            if (fuzzBody && (bodyTemplateEditor.getText() == null
                    || !bodyTemplateEditor.getText().toUpperCase().contains("FUZZ"))) {
                appendLog("[!] Body fuzzing is selected, but the body editor has no FUZZ token.");
                return;
            }
        }
        if (baselineStatus < 0 && baseMsg != null) {
            appendLog("[*] No baseline yet; fetching it first...");
            fetchBaseline();
            if (baselineStatus < 0) {
                appendLog("[!] Baseline fetch failed; aborting run.");
                return;
            }
        }
        if (worker != null && !worker.isDone()) {
            worker.cancel(true);
        }
        engine.setForceRawWire(useRawWireBox.isSelected());
        engine.setSoTimeoutSeconds((Integer) timeoutSpinner.getValue());

        final boolean fuzzMode = fuzzModeBox.isSelected();
        final int maxProbes = (Integer) maxProbesSpinner.getValue();
        final List<HttpMessage> runBases = new ArrayList<>();
        final List<Technique> runTechs = new ArrayList<>();
        if (fuzzMode) {
            // Fuzz mode sends ONE direct request per wordlist entry. Each word is
            // substituted for the selected targets (FUZZ in the URL, the per-rule
            // Find string in existing header values, or FUZZ in the body template)
            // and the resulting clone is sent with an identity technique so the
            // technique lists (and their bypasses) are not applied at all.
            try {
                java.util.List<String> words = new java.util.ArrayList<>();
                try (java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.FileReader(fuzzWordlistField.getText().trim()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty()) words.add(line);
                    }
                }
                if (words.isEmpty()) {
                    appendLog("[!] Wordlist is empty.");
                    return;
                }
                java.util.List<String> selected = words;
                if (maxProbes > 0 && words.size() > maxProbes) {
                    selected = words.subList(0, maxProbes);
                    appendLog("[*] Limiting fuzz run to the first " + maxProbes + " words.");
                }
                for (String word : selected) {
                    HttpMessage clone = baseMsg.cloneAll();
                    if (fuzzUrlBox.isSelected()) {
                        try {
                            String urlTemplate = urlField.getText().trim();
                            String urlMode = urlModeCombo.getSelectedItem().toString();
                            String fuzzed;
                            if (urlTemplate.toUpperCase().contains("FUZZ")) {
                                switch (urlMode) {
                                    case "APPEND":
                                        fuzzed = expandFuzz(urlTemplate, "") + word;
                                        break;
                                    case "PREPEND":
                                        fuzzed = word + expandFuzz(urlTemplate, "");
                                        break;
                                    case "REPLACE":
                                    default:
                                        fuzzed = expandFuzz(urlTemplate, word);
                                        break;
                                }
                            } else {
                                switch (urlMode) {
                                    case "APPEND":
                                        fuzzed = urlTemplate + word;
                                        break;
                                    case "PREPEND":
                                        fuzzed = word + urlTemplate;
                                        break;
                                    case "REPLACE":
                                    default:
                                        fuzzed = word;
                                        break;
                                }
                            }
                            org.apache.commons.httpclient.URI uri =
                                new org.apache.commons.httpclient.URI(fuzzed, true);
                            clone.getRequestHeader().setURI(uri);
                        } catch (Exception e) {
                            appendLog("[!] Bad fuzzed URL '" + urlField.getText().trim()
                                + "': " + e.getMessage());
                            continue;
                        }
                    }
                    if (fuzzHeaderBox.isSelected()) {
                        for (HacktorEngine.CustomHeader h : customHeaderModel.getRules()) {
                            applyFuzzHeader(clone, h, word);
                        }
                    }
                    if (fuzzBodyBox.isSelected()) {
                        applyFuzzBody(clone, bodyTemplateEditor.getText(),
                            bodyModeCombo.getSelectedItem().toString(), word);
                    }
                    runBases.add(clone);
                    String lbl = word;
                    runTechs.add(new Technique("Fuzz", lbl, "wordlist entry",
                        base -> base));
                }
                appendLog("[*] Fuzz mode: " + runBases.size() + " direct probes (one per word).");
            } catch (java.io.IOException e) {
                appendLog("[!] Failed to read wordlist: " + e.getMessage());
                return;
            }
        } else {
            List<Technique> enabled = techniqueModel.getAll().stream()
                .filter(Technique::isEnabled).collect(Collectors.toList());
            if (maxProbes > 0 && enabled.size() > maxProbes) {
                enabled = enabled.subList(0, maxProbes);
                appendLog("[*] Limiting run to the first " + maxProbes + " enabled techniques.");
            }
            if (enabled.isEmpty()) {
                appendLog("[!] No techniques enabled.");
                return;
            }
            for (int i = 0; i < enabled.size(); i++) {
                runBases.add(baseMsg);
            }
            runTechs.addAll(enabled);
        }

        final int totalProbes = runTechs.size();

        paused = false;
        runCancelled[0] = false;
        runStartTime = System.currentTimeMillis();
        candidateCount = 0;
        runButton.setEnabled(false);
        pauseButton.setEnabled(true);
        resumeButton.setEnabled(false);
        stopButton.setEnabled(true);
        exportButton.setEnabled(false);
        resendButton.setEnabled(false);
        copyUrlButton.setEnabled(false);
        copyCurlButton.setEnabled(false);
        progressBar.setValue(0);
        progressBar.setMaximum(totalProbes);
        progressBar.setString("0 / " + totalProbes);
        progressLabel.setText("Starting...");
        statsLabel.setText("Probes: 0 | Candidates: 0 | Elapsed: 0:00");
        resultsModel.clear();
        logArea.setText("");
        statsTimer.start();
        final int threadCount = (Integer) threadsSpinner.getValue();
        final int rateLimit = (Integer) rateLimitSpinner.getValue();
        final boolean retryOnError = retryOnErrorBox.isSelected();
        final boolean stopOnCandidate = stopOnCandidateBox.isSelected();
        final boolean backoffEnabled = backoffBox.isSelected();

        appendLog("[*] Running " + totalProbes + " probes..."
            + (threadCount > 1 ? " [threads: " + threadCount + "]" : "")
            + (rateLimit > 0 ? " [rate: " + rateLimit + "/sec]" : "")
            + (backoffEnabled ? " [exp. backoff]" : "")
            + " [timeout: " + timeoutSpinner.getValue() + "s]");

        worker = new SwingWorker<List<Result>, Object>() {

            private final List<Technique> techList = new ArrayList<>(runTechs);
            private final List<HttpMessage> baseList = new ArrayList<>(runBases);

            @Override
            protected List<Result> doInBackground() {
                if (threadCount <= 1) {
                    return runSequential();
                }
                return runParallel(threadCount);
            }

            private List<Result> runSequential() {
                List<Result> results = new ArrayList<>();
                HttpSender runSender = createSender();
                runSender.setFollowRedirect(followRedirectsBox.isSelected());
                final BackoffPacer pacer = backoffEnabled ? new BackoffPacer() : null;
                try {
                    int cur = 0;
                    long lastRequestTime = 0;
                    final long minInterval = rateLimit > 0 ? 1000L / rateLimit : 0;
                    for (int ti = 0; ti < techList.size(); ti++) {
                        if (isCancelled() || runCancelled[0]) break;
                        waitWhilePaused();
                        if (isCancelled() || runCancelled[0]) break;

                        long now = System.currentTimeMillis();
                        if (minInterval > 0 && lastRequestTime > 0) {
                            long wait = minInterval - (now - lastRequestTime);
                            if (wait > 0) {
                                try { Thread.sleep(wait); } catch (InterruptedException e) { break; }
                            }
                        }
                        lastRequestTime = System.currentTimeMillis();
                        if (pacer != null) {
                            try { pacer.await(); } catch (InterruptedException e) { break; }
                        }

                        Result r = probeWithRetry(techList.get(ti), baseList.get(ti),
                            runSender, retryOnError);
                        if (pacer != null) pacer.observe(looksThrottled(r));
                        cur++;
                        if (r != null) results.add(r);
                        publish(r, cur, totalProbes);
                        if (stopOnCandidate && r != null
                                && r.getVerdict() == Technique.Verdict.CANDIDATE) {
                            runCancelled[0] = true;
                            break;
                        }
                    }
                    return results;
                } finally {
                    runSender.shutdown();
                }
            }

            private List<Result> runParallel(int threads) {
                List<Result> results = new ArrayList<>();
                ExecutorService pool = Executors.newFixedThreadPool(threads);
                final BackoffPacer pacer = backoffEnabled ? new BackoffPacer() : null;
                try {
                    final long minInterval = rateLimit > 0 ? 1000L / rateLimit : 0;
                    List<Future<Result>> futures = new ArrayList<>();
                    for (int ti = 0; ti < techList.size(); ti++) {
                        if (isCancelled() || runCancelled[0]) break;
                        final Technique tech = techList.get(ti);
                        final HttpMessage base = baseList.get(ti);
                        futures.add(pool.submit(() -> {
                            if (isCancelled() || runCancelled[0]) return null;
                            waitWhilePaused();
                            if (isCancelled() || runCancelled[0]) return null;
                            if (minInterval > 0) sleepQuietly(minInterval);
                            if (pacer != null) {
                                try { pacer.await(); } catch (InterruptedException e) { return null; }
                            }
                            HttpSender s = createSender();
                            s.setFollowRedirect(followRedirectsBox.isSelected());
                            try {
                                Result r = probeWithRetry(tech, base, s, retryOnError);
                                if (pacer != null) pacer.observe(looksThrottled(r));
                                return r;
                            } finally {
                                s.shutdown();
                            }
                        }));
                    }
                    int cur = 0;
                    for (Future<Result> f : futures) {
                        if (isCancelled() || runCancelled[0]) {
                            f.cancel(true);
                            cur++;
                            publish(null, cur, totalProbes);
                            continue;
                        }
                        Result r;
                        try {
                            r = f.get(60, TimeUnit.SECONDS);
                        } catch (Exception e) {
                            r = null;
                        }
                        cur++;
                        if (r != null) results.add(r);
                        publish(r, cur, totalProbes);
                        if (stopOnCandidate && r != null
                                && r.getVerdict() == Technique.Verdict.CANDIDATE) {
                            runCancelled[0] = true;
                            break;
                        }
                    }
                    return results;
                } finally {
                    pool.shutdownNow();
                }
            }

            private Result probeWithRetry(Technique tech, HttpMessage base,
                    HttpSender s, boolean retry) {
                int attempts = retry ? 3 : 1;
                Result last = null;
                for (int a = 0; a < attempts; a++) {
                    if (a > 0) sleepQuietly(250);
                    last = engine.runOne(base, tech, s, suppressErrorsBox.isSelected(),
                        baselineStatus, baselineLen, base.getResponseBody().toString());
                    if (last != null || isCancelled() || runCancelled[0]) break;
                }
                return last;
            }

            private void waitWhilePaused() {
                while (paused && !isCancelled() && !runCancelled[0]) {
                    synchronized (pauseLock) {
                        try { pauseLock.wait(500); } catch (InterruptedException e) { break; }
                    }
                }
            }

            private void sleepQuietly(long ms) {
                if (ms <= 0) return;
                try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }

            @Override
            protected void process(List<Object> chunks) {
                int maxCur = progressBar.getValue();
                for (int i = 0; i < chunks.size(); i += 3) {
                    Result r = (Result) chunks.get(i);
                    int cur = (Integer) chunks.get(i + 1);
                    int tot = (Integer) chunks.get(i + 2);
                    if (cur > maxCur) maxCur = cur;
                    if (r != null) {
                        resultsModel.addResult(r);
                        if (r.getVerdict() == Technique.Verdict.CANDIDATE) {
                            candidateCount++;
                            appendLog(String.format("[!] CANDIDATE: %s -> %d (%d bytes, res=%s)",
                                r.getLabel(), liveStatus(r), liveLength(r), r.getResTime()));
                        }
                    }
                }
                int tot = progressBar.getMaximum();
                if (maxCur > tot) maxCur = tot;
                progressBar.setValue(maxCur);
                progressBar.setString(maxCur + " / " + tot);
                double pct = (maxCur * 100.0) / tot;
                progressLabel.setText(String.format("Running: %d/%d (%.0f%%)", maxCur, tot, pct));
                int last = resultsTable.getRowCount() - 1;
                if (last >= 0) {
                    resultsTable.scrollRectToVisible(resultsTable.getCellRect(last, 0, true));
                }
            }

            @Override
            protected void done() {
                statsTimer.stop();
                try {
                    List<Result> results = get();
                    onRunComplete(results, totalProbes);
                } catch (java.util.concurrent.CancellationException e) {
                    // Already handled by stopRun()
                } catch (Exception e) {
                    appendLog("[!] Error: " + e.getMessage());
                    setRunUiState(true);
                }
            }
        };
        worker.execute();
    }

    private void pauseRun() {
        if (worker != null && !worker.isCancelled() && !paused) {
            paused = true;
            pauseButton.setEnabled(false);
            resumeButton.setEnabled(true);
            progressLabel.setText(progressLabel.getText() + " [PAUSED]");
            appendLog("[*] Paused.");
        }
    }

    private void resumeRun() {
        if (worker != null && !worker.isCancelled() && paused) {
            paused = false;
            synchronized (pauseLock) { pauseLock.notifyAll(); }
            pauseButton.setEnabled(true);
            resumeButton.setEnabled(false);
            appendLog("[*] Resumed.");
        }
    }

    private void stopRun() {
        if (worker != null && !worker.isCancelled()) {
            paused = false;
            runCancelled[0] = true;
            synchronized (pauseLock) { pauseLock.notifyAll(); }
            worker.cancel(true);
            statsTimer.stop();
            appendLog("[*] Stopped by user.");
            runButton.setEnabled(true);
            pauseButton.setEnabled(false);
            resumeButton.setEnabled(false);
            stopButton.setEnabled(false);
            progressLabel.setText("Stopped");
        }
    }

    private void setRunUiState(boolean idle) {
        boolean canRun = (fuzzModeBox.isSelected() || countEnabledTechniques() > 0) && baseMsg != null;
        runButton.setEnabled(idle && canRun);
        pauseButton.setEnabled(!idle);
        resumeButton.setEnabled(false);
        stopButton.setEnabled(!idle);
        exportButton.setEnabled(!idle || resultsModel.getRowCount() > 0);
        if (idle) showSelectedResult();
    }

    private long countEnabledTechniques() {
        return techniqueModel.getAll().stream().filter(Technique::isEnabled).count();
    }

    private void onRunComplete(List<Result> results, int probeCount) {
        long elapsed = System.currentTimeMillis() - runStartTime;
        double secs = elapsed / 1000.0;
        resultsModel.setResults(results);
        long candidates = results.stream()
            .filter(r -> r.getVerdict() == Technique.Verdict.CANDIDATE).count();
        long suppressed = results.stream()
            .filter(r -> r.getVerdict() == Technique.Verdict.SUPPRESSED).count();
        summaryLabel.setText(String.format(
            "Candidates: %d | Suppressed: %d | Changes: %d | Probes: %d in %.1fs",
            candidates, suppressed, results.size(), probeCount, secs));
        progressBar.setValue(progressBar.getMaximum());
        progressBar.setString("Complete");
        progressLabel.setText(String.format("Complete: %d results in %.1fs",
            results.size(), secs));
        statsLabel.setText(String.format("Probes: %d | Candidates: %d | Elapsed: %d:%02d",
            probeCount, candidateCount, elapsed / 60000, (elapsed / 1000) % 60));
        setRunUiState(true);
        appendLog(String.format("[*] Done: %d results in %.1fs", results.size(), secs));
        if (candidates > 0) {
            appendLog("[!] " + candidates + " CANDIDATE BYPASS"
                + (candidates > 1 ? "ES" : "") + " FOUND");
            autoSelectFirstCandidate();
        }
    }

    private void autoSelectFirstCandidate() {
        for (int i = 0; i < resultsModel.getRowCount(); i++) {
            Result r = resultsModel.getAt(i);
            if (r != null && r.getVerdict() == Technique.Verdict.CANDIDATE) {
                resultsTable.setRowSelectionInterval(i, i);
                return;
            }
        }
    }

    private void updateStatsLabel() {
        if (statsTimer.isRunning()) {
            long millis = System.currentTimeMillis() - runStartTime;
            statsLabel.setText(String.format("Probes: %d | Candidates: %d | Elapsed: %d:%02d",
                progressBar.getValue(), candidateCount, millis / 60000, (millis / 1000) % 60));
        }
    }

    private int liveLength(Result r) {
        HttpMessage m = r.getMessage();
        if (m == null || m.getResponseBody() == null) return r.getLength();
        return m.getResponseBody().toString().length();
    }

    /** Renders a phase time in milliseconds; -1 (unknown phase) becomes "—". */

    // ─── Logging ────────────────────────────────────────────────────────

    private static String csvEscape(String s) {
        if (s == null) return "";
        if (!s.isEmpty() && (s.charAt(0) == '=' || s.charAt(0) == '+'
                || s.charAt(0) == '-' || s.charAt(0) == '@' || s.charAt(0) == '\t')) {
            s = "'" + s;
        }
        if (s.contains("\"") || s.contains(",") || s.contains("\n")) {
            return s.replace("\"", "\"\"");
        }
        return s;
    }

    private void appendLog(String msg) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(msg + "\n");
            int cap = logCapChars();
            int len = logArea.getDocument().getLength();
            if (len > cap && cap > 0) {
                try {
                    logArea.getDocument().remove(0, len - cap);
                } catch (Exception ignored) {
                }
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private static String tierName(VulnCatalog.Tier t) {
        if (t == null) return "Classic";
        try {
            String n = t.name();
            if (n.isEmpty()) return "Classic";
            return n.charAt(0) + n.substring(1).toLowerCase();
        } catch (Exception ex) {
            return "Classic";
        }
    }

    private static void copyToClipboard(String s) {
        try {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(s), null);
        } catch (Exception ignored) {
        }
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    private static String buildCurl(HttpMessage m) {
        try {
            String method = m.getRequestHeader().getMethod();
            String url = m.getRequestHeader().getURI().toString();
            StringBuilder sb = new StringBuilder("curl -k -i -X ")
                .append(method).append(' ').append(shellQuote(url));
            String headers = m.getRequestHeader().getHeadersAsString();
            if (headers != null) {
                for (String line : headers.split("\r\n")) {
                    int ci = line.indexOf(':');
                    if (ci <= 0 || line.startsWith("Content-Length")) continue;
                    sb.append(" -H ").append(shellQuote(line.trim()));
                }
            }
            String body = m.getRequestBody().toString();
            if (body != null && !body.isEmpty()) {
                sb.append(" --data-binary ").append(shellQuote(body));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ─── HTTP Sender ────────────────────────────────────────────────────

    /** Replaces every case-insensitive FUZZ token with the given word. */
    private static String expandFuzz(String template, String word) {
        if (template == null) return "";
        return template.replaceAll("(?i)FUZZ",
            java.util.regex.Matcher.quoteReplacement(word));
    }

    /** Fuzz-mode header substitution: for a rule (Name|Find|Mode), each word replaces
     *  the Find string inside the base request's current value of that header; if the
     *  Find string is blank the rule falls back to FUZZ tokens in the value; if the
     *  value has neither, the word becomes the value. Then the mode merges the result:
     *  SET replaces, APPEND joins after, PREPEND inserts before the existing value. */
    private static void applyFuzzHeader(HttpMessage clone, HacktorEngine.CustomHeader h, String word) {
        if (h == null || h.getName() == null || h.getName().trim().isEmpty()) return;
        try {
            String name = expandFuzz(h.getName().trim(), word);
            String find = h.getFind();
            if (find == null || find.isEmpty()) find = "FUZZ";
            String existing = clone.getRequestHeader().getHeader(name);
            String base = existing == null ? "" : existing;
            String replaced;
            String haystack = base;
            if (haystack.toUpperCase().contains(find.toUpperCase())) {
                replaced = haystack.replaceAll("(?i)" + java.util.regex.Pattern.quote(find),
                    java.util.regex.Matcher.quoteReplacement(word));
            } else {
                replaced = word;
            }
            String next;
            switch (h.getMode()) {
                case APPEND:
                    next = base.isEmpty() ? replaced : base + ", " + replaced;
                    break;
                case PREPEND:
                    next = base.isEmpty() ? replaced : replaced + ", " + base;
                    break;
                case SET:
                default:
                    next = replaced;
                    break;
            }
            if (!next.isEmpty()) clone.getRequestHeader().setHeader(name, next);
        } catch (Exception ignored) {}
    }

    /** Fuzz-mode body substitution: FUZZ tokens in the template are replaced per word,
     *  then the mode merges the template with the original body (REPLACE / APPEND /
     *  PREPEND) and the Content-Length is refreshed. */
    private static void applyFuzzBody(HttpMessage clone, String template, String mode, String word) {
        if (template == null) template = "";
        try {
            String injected = expandFuzz(template, word);
            String existing = clone.getRequestBody() != null ? clone.getRequestBody().toString() : "";
            String next;
            if (mode == null) mode = "REPLACE";
            switch (mode) {
                case "APPEND":
                    next = existing + injected;
                    break;
                case "PREPEND":
                    next = injected + existing;
                    break;
                case "REPLACE":
                default:
                    next = injected;
                    break;
            }
            clone.setRequestBody(next);
            clone.getRequestHeader().setContentLength(next.length());
        } catch (Exception ignored) {}
    }

    private HttpSender createSender() {
        return new HttpSender(
            Model.getSingleton().getOptionsParam().getConnectionParam(),
            true,
            HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    public void shutdown() {
        stopRun();
        stopOauth();
    }

    // ─── Table models ───────────────────────────────────────────────────

    private class CustomHeaderTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 2L;
        private final List<HacktorEngine.CustomHeader> rules = new ArrayList<>();

        void addRule(HacktorEngine.CustomHeader h) {
            rules.add(h);
            fireTableDataChanged();
        }

        void removeAt(int row) {
            if (row >= 0 && row < rules.size()) {
                rules.remove(row);
                fireTableDataChanged();
            }
        }

        void clear() {
            rules.clear();
            fireTableDataChanged();
        }

        List<HacktorEngine.CustomHeader> getRules() {
            return new ArrayList<>(rules);
        }

        HacktorEngine.CustomHeader getAt(int row) {
            return (row >= 0 && row < rules.size()) ? rules.get(row) : null;
        }

        @Override public int getRowCount() { return rules.size(); }
        @Override public int getColumnCount() { return 3; }
        @Override public String getColumnName(int c) {
            switch (c) {
                case 0: return "Name";
                case 1: return "Find";
                case 2: return "Mode";
                default: return "";
            }
        }
        @Override public boolean isCellEditable(int r, int c) { return true; }
        @Override public Object getValueAt(int row, int col) {
            HacktorEngine.CustomHeader h = getAt(row);
            if (h == null) return null;
            switch (col) {
                case 0: return h.getName();
                case 1: return h.getFind().isEmpty() ? "FUZZ" : h.getFind();
                case 2: return h.getMode();
                default: return "";
            }
        }
        @Override public void setValueAt(Object val, int row, int col) {
            HacktorEngine.CustomHeader h = getAt(row);
            if (h == null || val == null) return;
            switch (col) {
                case 0:
                    h.setName(val.toString().trim());
                    break;
                case 1: {
                    String find = val.toString().trim();
                    h.setFind("FUZZ".equalsIgnoreCase(find) ? "" : find);
                    break;
                }
                case 2:
                    try {
                        h.setMode(HacktorEngine.HeaderMode.valueOf(val.toString().toUpperCase()));
                    } catch (Exception ignored) {
                    }
                    break;
                default:
                    return;
            }
            fireTableCellUpdated(row, col);
            saveHeaders();
        }
    }

    private class FixedHeaderTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private final List<HacktorEngine.CustomHeader> rows = new ArrayList<>();

        void addRow(HacktorEngine.CustomHeader h) {
            rows.add(h);
            fireTableDataChanged();
        }

        void removeAt(int row) {
            if (row >= 0 && row < rows.size()) {
                rows.remove(row);
                fireTableDataChanged();
            }
        }

        List<HacktorEngine.CustomHeader> getFixedHeaders() {
            return new ArrayList<>(rows);
        }

        HacktorEngine.CustomHeader getAt(int row) {
            return (row >= 0 && row < rows.size()) ? rows.get(row) : null;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int c) { return c == 0 ? "Header" : "Value"; }
        @Override public boolean isCellEditable(int r, int c) { return true; }
        @Override public Object getValueAt(int row, int col) {
            HacktorEngine.CustomHeader h = getAt(row);
            if (h == null) return null;
            return col == 0 ? h.getName()
                : h.getValues().isEmpty() ? "" : String.join(", ", h.getValues());
        }
        @Override public void setValueAt(Object val, int row, int col) {
            HacktorEngine.CustomHeader h = getAt(row);
            if (h == null || val == null) return;
            if (col == 0) {
                h.setName(val.toString().trim());
            } else {
                List<String> vals = new ArrayList<>();
                vals.add(val.toString());
                h.setValues(vals);
            }
            syncFixedHeadersToEngine();
            saveFixedHeaders();
            fireTableCellUpdated(row, col);
        }
    }

    private class TechniqueTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 1L;
        private List<Technique> all = new ArrayList<>();
        private List<Technique> visible = new ArrayList<>();

        void setRows(List<Technique> techs) {
            all = new ArrayList<>(techs);
            recompute();
        }

        void setFilter(Predicate<Technique> pred) {
            visible = pred == null ? new ArrayList<>(all)
                : all.stream().filter(pred).collect(Collectors.toList());
            fireTableDataChanged();
        }

        void recompute() {
            fireTableDataChanged();
        }

        List<Technique> getAll() { return Collections.unmodifiableList(all); }
        Technique getAt(int row) {
            return (row >= 0 && row < visible.size()) ? visible.get(row) : null;
        }
        void addCustom(Technique t) { all.add(t); visible = new ArrayList<>(all); fireTableDataChanged(); }
        void removeCustom(Technique t) { all.remove(t); visible = new ArrayList<>(all); fireTableDataChanged(); }

        @Override public int getRowCount() { return visible.size(); }
        @Override public int getColumnCount() { return 5; }
        @Override public String getColumnName(int c) {
            switch (c) {
                case 0: return "On";
                case 1: return "Category";
                case 2: return "Technique";
                case 3: return "Tier";
                case 4: return "Description";
                default: return "";
            }
        }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return false; }
        @Override public Object getValueAt(int row, int col) {
            if (row >= visible.size()) return null;
            Technique t = visible.get(row);
            switch (col) {
                case 0: return t.isEnabled();
                case 1: return t.getFamily();
                case 2: return t.getLabel();
                case 3: return tierName(t.getTier());
                case 4: return t.getDescription();
                default: return "";
            }
        }
        @Override public void setValueAt(Object val, int row, int col) {
            if (col == 0 && row < visible.size()) {
                visible.get(row).setEnabled(Boolean.TRUE.equals(val));
                fireTableCellUpdated(row, col);
                afterTechniqueToggle();
            }
        }
    }

    private class ResultsTableModel extends AbstractTableModel {
        private static final long serialVersionUID = 2L;
        private List<Result> all = new ArrayList<>();
        private List<Result> visible = new ArrayList<>();
        private Predicate<Result> filter = null;
        /** Hard cap on retained rows. Each Result holds a full HttpMessage, so without
         *  this every run (and every live result during it) accumulates unboundedly. */
        private int maxResults = 10_000;

        synchronized void setMaxResults(int n) {
            maxResults = Math.max(1, n);
            evictOverCap();
        }

        synchronized void setResults(List<Result> r) {
            all = new ArrayList<>(r);
            evictOverCap();
            recompute();
        }

        private void evictOverCap() {
            boolean pruned = false;
            while (all.size() > maxResults && all.size() > 1) {
                pruneOldestNonCandidate();
                pruned = true;
            }
            if (pruned) recompute();
        }

        /** Drops the oldest retained row, preferring to evict non-candidate verdicts
         *  so the full request/response detail is preserved for likely findings. */
        private void pruneOldestNonCandidate() {
            for (int i = 0; i < all.size(); i++) {
                if (all.get(i).getVerdict() != Technique.Verdict.CANDIDATE) {
                    all.remove(i);
                    return;
                }
            }
            all.remove(0);
        }

        synchronized void addResult(Result r) {
            all.add(r);
            if (all.size() > maxResults && all.size() > 1) {
                pruneOldestNonCandidate();
                recompute();
                return;
            }
            if (filter == null || filter.test(r)) {
                visible.add(r);
                fireTableRowsInserted(visible.size() - 1, visible.size() - 1);
            }
        }

        synchronized void clear() {
            all.clear();
            visible.clear();
            fireTableDataChanged();
        }

        synchronized void setFilter(Predicate<Result> pred) {
            this.filter = pred;
            recompute();
        }

        private void recompute() {
            visible = (filter == null) ? new ArrayList<>(all)
                : all.stream().filter(filter).collect(Collectors.toList());
            fireTableDataChanged();
        }

        List<Result> getResults() { return all; }
        Result getAt(int r) { return (r >= 0 && r < visible.size()) ? visible.get(r) : null; }

        @Override public int getRowCount() { return visible.size(); }
        @Override public int getColumnCount() { return 10; }
        @Override public String getColumnName(int c) {
            switch (c) {
                case 0: return "#";
                case 1: return "Category";
                case 2: return "Technique";
                case 3: return "Path";
                case 4: return "Status";
                case 5: return "Length";
                case 6: return "Base";
                case 7: return "Verdict";
                case 8: return "Req ms";
                case 9: return "Res ms";
                default: return "";
            }
        }
        @Override public Object getValueAt(int row, int col) {
            if (row >= visible.size()) return null;
            Result r = visible.get(row);
            switch (col) {
                case 0: return row + 1;
                case 1: return r.getFamily();
                case 2: return r.getLabel();
                case 3: return r.getPath();
                case 4: return liveStatus(r);
                case 5: return liveLength(r);
                case 6: return r.getBaselineStatus();
                case 7: return r.getVerdict().toString();
                case 8: return r.getReqTime();
                case 9: return r.getResTime();
                default: return "";
            }
        }
    }

    // ─── Custom technique dialog (dark themed) ──────────────────────────

    private static class CustomTechDialog extends JDialog {
        private static final long serialVersionUID = 1L;
        private boolean confirmed = false;
        private final JTextField nameField = new JTextField(20);
        private final JTextField categoryField = new JTextField(15);
        private final JTextField descField = new JTextField(30);
        private final JComboBox<String> typeCombo = new JComboBox<>(
            new String[]{"Path Replacement", "Header Override", "Placement Probe"});
        private final JTextField pathField = new JTextField(25);
        private final JTextField headerNameField = new JTextField(15);
        private final JTextField headerValueField = new JTextField(20);
        private final JComboBox<String> placementClassCombo = new JComboBox<>();
        private final JComboBox<String> placementCombo = new JComboBox<>(VulnCatalog.PLACEMENT_DISPLAY);
        private final JTextField payloadField = new JTextField(24);
        private final JComboBox<String> encodeCombo = new JComboBox<>(PayloadEncoder.displayNames());

        CustomTechDialog(Window owner, String title, Technique existing) {
            super(owner, title, ModalityType.APPLICATION_MODAL);
            setLayout(new BorderLayout(8, 8));
            getRootPane().setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
            getContentPane().setBackground(BG);

            JPanel form = new JPanel(new GridBagLayout());
            form.setBackground(BG);
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(3, 4, 3, 4);
            g.anchor = GridBagConstraints.WEST;
            g.fill = GridBagConstraints.HORIZONTAL;

            int row = 0;
            addRow(form, g, row++, "Name:", nameField);
            addRow(form, g, row++, "Category:", categoryField);
            addRow(form, g, row++, "Description:", descField);
            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel typeLbl = new JLabel("Type:");
            typeLbl.setForeground(FG);
            form.add(typeLbl, g);
            g.gridx = 1; g.weightx = 1;
            typeCombo.setBackground(BG_DARK);
            typeCombo.setForeground(FG);
            form.add(typeCombo, g);
            row++;
            addRow(form, g, row++, "Path:", pathField);
            addRow(form, g, row++, "Header Name:", headerNameField);
            addRow(form, g, row++, "Header Value:", headerValueField);

            for (VulnCatalog.VulnClass vc : VulnCatalog.getClasses()) {
                placementClassCombo.addItem(vc.getFamily());
            }
            if (placementClassCombo.getItemCount() == 0) {
                placementClassCombo.addItem("401/403 Bypass");
            }
            addRow(form, g, row++, "Vuln Class:", placementClassCombo);
            addRow(form, g, row++, "Placement:", placementCombo);
            addRow(form, g, row++, "Payload:", payloadField);
            addRow(form, g, row++, "Encode:", encodeCombo);

            add(form, BorderLayout.CENTER);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttons.setBackground(BG);
            JButton ok = new JButton("OK");
            themeButton(ok);
            JButton cancel = new JButton("Cancel");
            themeButton(cancel);
            buttons.add(ok);
            buttons.add(cancel);
            add(buttons, BorderLayout.SOUTH);

            ok.addActionListener(e -> {
                if (nameField.getText().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Name is required.", "Validation",
                        JOptionPane.WARNING_MESSAGE);
                    return;
                }
                confirmed = true;
                dispose();
            });
            cancel.addActionListener(e -> dispose());

            if (existing != null) {
                nameField.setText(existing.getLabel());
                categoryField.setText(existing.getFamily());
                descField.setText(existing.getDescription());
                if (existing.getCustomPlacement() != null) {
                    typeCombo.setSelectedIndex(2);
                    payloadField.setText(existing.getCustomPayload());
                } else if (existing.getCustomPath() != null) {
                    typeCombo.setSelectedIndex(0);
                    pathField.setText(existing.getCustomPath());
                } else if (existing.getCustomHeaderName() != null) {
                    typeCombo.setSelectedIndex(1);
                    headerNameField.setText(existing.getCustomHeaderName());
                    headerValueField.setText(existing.getCustomHeaderValue());
                }
            }
            typeCombo.addActionListener(e -> {
                int idx = typeCombo.getSelectedIndex();
                boolean isPath = idx == 0;
                boolean isHeader = idx == 1;
                boolean isPlacement = idx == 2;
                pathField.setEnabled(isPath);
                headerNameField.setEnabled(isHeader);
                headerValueField.setEnabled(isHeader);
                placementClassCombo.setEnabled(isPlacement);
                placementCombo.setEnabled(isPlacement);
                payloadField.setEnabled(isPlacement);
                encodeCombo.setEnabled(isPlacement);
            });
            {
                int idx = typeCombo.getSelectedIndex();
                boolean isPath = idx == 0;
                boolean isHeader = idx == 1;
                boolean isPlacement = idx == 2;
                pathField.setEnabled(isPath);
                headerNameField.setEnabled(isHeader);
                headerValueField.setEnabled(isHeader);
                placementClassCombo.setEnabled(isPlacement);
                placementCombo.setEnabled(isPlacement);
                payloadField.setEnabled(isPlacement);
                encodeCombo.setEnabled(isPlacement);
            }

            for (JTextField tf : new JTextField[]{nameField, categoryField, descField,
                    pathField, headerNameField, headerValueField, payloadField}) {
                tf.setBackground(BG_DARK);
                tf.setForeground(FG);
                tf.setCaretColor(FG);
            }
            placementClassCombo.setBackground(BG_DARK);
            placementClassCombo.setForeground(FG);
            placementCombo.setBackground(BG_DARK);
            placementCombo.setForeground(FG);
            encodeCombo.setBackground(BG_DARK);
            encodeCombo.setForeground(FG);

            pack();
            setMinimumSize(new Dimension(420, 300));
            setLocationRelativeTo(owner);
        }

        private void addRow(JPanel p, GridBagConstraints g, int row, String label, JComponent field) {
            g.gridx = 0; g.gridy = row; g.weightx = 0;
            JLabel lbl = new JLabel(label);
            lbl.setForeground(FG);
            p.add(lbl, g);
            g.gridx = 1; g.weightx = 1;
            p.add(field, g);
        }

        boolean isConfirmed() { return confirmed; }

        Technique buildTechnique() {
            String name = sanitize(nameField.getText().trim());
            String cat = sanitize(categoryField.getText().trim());
            String desc = sanitize(descField.getText().trim());
            if (name.isEmpty()) return null;
            if (cat.isEmpty() && typeCombo.getSelectedIndex() != 2) cat = "Custom";
            if (desc.isEmpty()) desc = "User-defined technique";
            if (typeCombo.getSelectedIndex() == 2) {
                String family = sanitize((String) placementClassCombo.getSelectedItem());
                if (family.isEmpty()) family = "Custom";
                String payload = sanitize(payloadField.getText().trim());
                if (payload.isEmpty()) return null;
                payload = encodePayload(payload);
                String placement = VulnCatalog.placementKind(
                    (String) placementCombo.getSelectedItem());
                return new Technique(family, name, desc, placement, payload);
            } else if (typeCombo.getSelectedIndex() == 0) {
                String path = sanitize(pathField.getText().trim());
                if (path.isEmpty()) return null;
                return new Technique(cat, name, desc, path);
            } else {
                String hName = sanitize(headerNameField.getText().trim());
                String hValue = sanitize(headerValueField.getText().trim());
                if (hName.isEmpty()) return null;
                return new Technique(cat, name, desc, hName, hValue, false);
            }
        }

        void applyTo(Technique t) {
            if (typeCombo.getSelectedIndex() == 2) {
                t.setCustomPath(null);
                t.setCustomHeaderName(null);
                t.setCustomHeaderValue(null);
                t.setCustomPlacement(VulnCatalog.placementKind(
                    (String) placementCombo.getSelectedItem()));
                t.setCustomPayload(encodePayload(sanitize(payloadField.getText().trim())));
            } else if (typeCombo.getSelectedIndex() == 0) {
                t.setCustomPath(pathField.getText().trim());
                t.setCustomHeaderName(null);
                t.setCustomHeaderValue(null);
                t.setCustomPlacement(null);
                t.setCustomPayload(null);
            } else {
                t.setCustomPath(null);
                t.setCustomHeaderName(headerNameField.getText().trim());
                t.setCustomHeaderValue(headerValueField.getText().trim());
                t.setCustomPlacement(null);
                t.setCustomPayload(null);
            }
        }

        private static String sanitize(String s) {
            if (s == null) return "";
            return s.replaceAll("[\\r\\n\\x00]", "").trim();
        }

        /** Applies the selected Recode-style encoder to a custom placement payload. */
        private String encodePayload(String payload) {
            if (payload == null || payload.isEmpty()) return payload;
            PayloadEncoder.Encoder enc = PayloadEncoder.fromDisplay(
                (String) encodeCombo.getSelectedItem());
            if (enc == PayloadEncoder.Encoder.NONE) return payload;
            return PayloadEncoder.encode(payload, enc);
        }
    }
}