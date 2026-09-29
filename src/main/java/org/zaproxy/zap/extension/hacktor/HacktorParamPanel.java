package org.zaproxy.zap.extension.hacktor;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import org.parosproxy.paros.view.AbstractParamPanel;

/**
 * Hacktor's entry in ZAP's Options dialog.
 *
 * <p>Registered with {@code ExtensionHookView.addOptionPanel(...)} so the settings
 * are visible, documented and importable/exportable alongside core ZAP options
 * rather than hidden inside the work panel.
 *
 * <p>This panel edits the same {@link HacktorParam} the work panel does, and it uses
 * ZAP's normal Apply/Revert lifecycle: {@link #initParam(Object)} loads, edits are
 * staged, and {@link #saveParam(Object)} commits. Because the work panel saves on
 * every control change, applying from here simply writes the staged values through
 * the same object both views share.
 */
public class HacktorParamPanel extends AbstractParamPanel {

    private static final Color BG_PANEL = new Color(0x32, 0x32, 0x32);
    private static final Color FG_BRIGHT = new Color(0xAF, 0xAF, 0xAF);
    private static final Color FG_DIM = new Color(0x80, 0x80, 0x80);

    private final JCheckBox followRedirectsBox = new JCheckBox("Follow redirects");
    private final JCheckBox suppressErrorsBox = new JCheckBox("Suppress custom error pages");
    private final JCheckBox stopOnCandidateBox = new JCheckBox("Stop on first candidate");
    private final JCheckBox retryOnErrorBox = new JCheckBox("Retry on network error");
    private final JCheckBox useRawWireBox = new JCheckBox("Raw wire for ambiguous requests");
    private final JCheckBox backoffBox = new JCheckBox("Exponential backoff on 403/429");
    private final JCheckBox candidatesOnlyBox = new JCheckBox("Candidates only");
    private final JCheckBox errorsOnlyBox = new JCheckBox("Errors only");
    private final JCheckBox exactWireBox = new JCheckBox("Show exact wire for results");
    private final JCheckBox showCustomOnlyBox = new JCheckBox("Custom techniques only");
    private final JCheckBox classicTierBox = new JCheckBox("Classic");
    private final JCheckBox rareTierBox = new JCheckBox("Rare");
    private final JCheckBox novelTierBox = new JCheckBox("Novel");
    private final JCheckBox oauthClassicBox = new JCheckBox("Classic");
    private final JCheckBox oauthRareBox = new JCheckBox("Rare");
    private final JCheckBox oauthNovelBox = new JCheckBox("Novel");

    private final JSpinner rateLimitSpinner =
        new JSpinner(new SpinnerNumberModel(0, 0, 10000, 1));
    private final JSpinner threadsSpinner =
        new JSpinner(new SpinnerNumberModel(1, 1, 16, 1));
    private final JSpinner timeoutSpinner =
        new JSpinner(new SpinnerNumberModel(5, 1, 120, 1));
    private final JSpinner maxProbesSpinner =
        new JSpinner(new SpinnerNumberModel(0, 0, 200000, 1));
    private final JSpinner maxResultsSpinner =
        new JSpinner(new SpinnerNumberModel(10000, 1000, 200000, 1000));
    private final JSpinner logCapSpinner =
        new JSpinner(new SpinnerNumberModel(500, 25, 10000, 25));

    private final JTextField oobUrlField = new JTextField(28);
    private final JTextField wordlistField = new JTextField(28);

    public HacktorParamPanel() {
        setLayout(new BorderLayout());
        setBackground(BG_PANEL);
        setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        add(buildBody(), BorderLayout.CENTER);

        for (JCheckBox cb : allBoxes()) {
            theme(cb);
        }
        for (JSpinner sp : new JSpinner[]{rateLimitSpinner, threadsSpinner, timeoutSpinner,
                maxProbesSpinner, maxResultsSpinner, logCapSpinner}) {
            theme(sp);
        }
        for (JTextField tf : new JTextField[]{oobUrlField, wordlistField}) {
            theme(tf);
        }
    }

    private JComponent buildBody() {
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(BG_PANEL);
        body.add(section("General"));
        body.add(checks(followRedirectsBox, suppressErrorsBox, stopOnCandidateBox,
            retryOnErrorBox, useRawWireBox, backoffBox, candidatesOnlyBox, errorsOnlyBox,
            exactWireBox, showCustomOnlyBox));
        body.add(spinners("Rate limit (0 = unlimited)", rateLimitSpinner,
            "Threads", threadsSpinner, "Timeout (s)", timeoutSpinner));
        body.add(spinners("Max probes (0 = unlimited)", maxProbesSpinner,
            "Max results", maxResultsSpinner, "Log cap", logCapSpinner));
        body.add(Box.createVerticalStrut(8));

        body.add(section("Technique tiers"));
        JPanel tiers = new JPanel(new GridBagLayout());
        tiers.setBackground(BG_PANEL);
        tiers.setOpaque(false);
        grid(tiers, 0, 0, label("Web request"));
        grid(tiers, 1, 0, checks(classicTierBox, rareTierBox, novelTierBox));
        grid(tiers, 0, 1, label("OAuth"));
        grid(tiers, 1, 1, checks(oauthClassicBox, oauthRareBox, oauthNovelBox));
        body.add(tiers);
        body.add(Box.createVerticalStrut(8));

        body.add(section("Out-of-band and wordlist"));
        JPanel text = new JPanel(new GridBagLayout());
        text.setBackground(BG_PANEL);
        text.setOpaque(false);
        grid(text, 0, 0, label("OOB callback URL"));
        grid(text, 1, 0, oobUrlField);
        grid(text, 0, 1, label("Fuzz wordlist"));
        grid(text, 1, 1, wordlistField);
        body.add(text);
        return body;
    }

    private JLabel section(String title) {
        JLabel l = new JLabel(title);
        l.setForeground(FG_BRIGHT);
        l.setBorder(BorderFactory.createEmptyBorder(6, 0, 4, 0));
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    private JComponent checks(JCheckBox... boxes) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.setBackground(BG_PANEL);
        p.setOpaque(false);
        for (JCheckBox b : boxes) {
            p.add(b);
            p.add(Box.createHorizontalStrut(8));
        }
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    private JComponent spinners(String label1, JSpinner s1, String label2, JSpinner s2,
            String label3, JSpinner s3) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.X_AXIS));
        p.setBackground(BG_PANEL);
        p.setOpaque(false);
        p.add(new JLabel(label1));
        p.add(Box.createHorizontalStrut(4));
        p.add(s1);
        p.add(Box.createHorizontalStrut(12));
        p.add(new JLabel(label2));
        p.add(Box.createHorizontalStrut(4));
        p.add(s2);
        p.add(Box.createHorizontalStrut(12));
        p.add(new JLabel(label3));
        p.add(Box.createHorizontalStrut(4));
        p.add(s3);
        for (java.awt.Component c : p.getComponents()) {
            if (c instanceof JLabel) {
                ((JLabel) c).setForeground(FG_DIM);
            }
        }
        p.setAlignmentX(LEFT_ALIGNMENT);
        return p;
    }

    private static void grid(JPanel p, int x, int y, java.awt.Component c) {
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = x;
        g.gridy = y;
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;
        if (x == 1) {
            g.weightx = 1.0;
            g.fill = GridBagConstraints.HORIZONTAL;
        }
        p.add(c, g);
    }

    private static JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(FG_DIM);
        return l;
    }

    private void theme(JComponent c) {
        c.setBackground(BG_PANEL);
        c.setForeground(FG_BRIGHT);
        c.setOpaque(true);
        if (c instanceof JSpinner) {
            java.awt.Component ed = ((JSpinner) c).getEditor();
            if (ed != null) {
                ed.setBackground(BG_PANEL);
                ed.setForeground(FG_BRIGHT);
            }
            if (((JSpinner) c).getEditor() instanceof JTextField) {
                ((JTextField) ((JSpinner) c).getEditor()).setCaretColor(FG_BRIGHT);
            }
        }
        if (c instanceof JTextField) {
            ((JTextField) c).setCaretColor(FG_BRIGHT);
        }
        if (c instanceof JCheckBox) {
            c.setOpaque(false);
        }
    }

    private JCheckBox[] allBoxes() {
        return new JCheckBox[]{followRedirectsBox, suppressErrorsBox, stopOnCandidateBox,
            retryOnErrorBox, useRawWireBox, backoffBox, candidatesOnlyBox, errorsOnlyBox,
            exactWireBox, showCustomOnlyBox, classicTierBox, rareTierBox, novelTierBox,
            oauthClassicBox, oauthRareBox, oauthNovelBox};
    }

    @Override
    public void initParam(Object o) {
        if (!(o instanceof HacktorParam)) {
            return;
        }
        HacktorParam p = (HacktorParam) o;
        p.ensureConfig();
        followRedirectsBox.setSelected(p.isFollowRedirects());
        suppressErrorsBox.setSelected(p.isSuppressErrors());
        stopOnCandidateBox.setSelected(p.isStopOnCandidate());
        retryOnErrorBox.setSelected(p.isRetryOnError());
        useRawWireBox.setSelected(p.isUseRawWire());
        backoffBox.setSelected(p.isBackoff());
        candidatesOnlyBox.setSelected(p.isCandidatesOnly());
        errorsOnlyBox.setSelected(p.isErrorsOnly());
        exactWireBox.setSelected(p.isExactWire());
        showCustomOnlyBox.setSelected(p.isShowCustomOnly());
        classicTierBox.setSelected(p.isClassicTier());
        rareTierBox.setSelected(p.isRareTier());
        novelTierBox.setSelected(p.isNovelTier());
        oauthClassicBox.setSelected(p.isOauthClassic());
        oauthRareBox.setSelected(p.isOauthRare());
        oauthNovelBox.setSelected(p.isOauthNovel());
        rateLimitSpinner.setValue(p.getRateLimit());
        threadsSpinner.setValue(p.getThreads());
        timeoutSpinner.setValue(p.getTimeout());
        maxProbesSpinner.setValue(p.getMaxProbes());
        maxResultsSpinner.setValue(p.getMaxResults());
        logCapSpinner.setValue(p.getLogCap());
        oobUrlField.setText(p.getOobUrl());
        wordlistField.setText(p.getWordlist());
    }

    @Override
    public void saveParam(Object o) {
        if (!(o instanceof HacktorParam)) {
            return;
        }
        HacktorParam p = (HacktorParam) o;
        p.setFollowRedirects(followRedirectsBox.isSelected());
        p.setSuppressErrors(suppressErrorsBox.isSelected());
        p.setStopOnCandidate(stopOnCandidateBox.isSelected());
        p.setRetryOnError(retryOnErrorBox.isSelected());
        p.setUseRawWire(useRawWireBox.isSelected());
        p.setBackoff(backoffBox.isSelected());
        p.setCandidatesOnly(candidatesOnlyBox.isSelected());
        p.setErrorsOnly(errorsOnlyBox.isSelected());
        p.setExactWire(exactWireBox.isSelected());
        p.setShowCustomOnly(showCustomOnlyBox.isSelected());
        p.setClassicTier(classicTierBox.isSelected());
        p.setRareTier(rareTierBox.isSelected());
        p.setNovelTier(novelTierBox.isSelected());
        p.setOauthClassic(oauthClassicBox.isSelected());
        p.setOauthRare(oauthRareBox.isSelected());
        p.setOauthNovel(oauthNovelBox.isSelected());
        p.setRateLimit((Integer) rateLimitSpinner.getValue());
        p.setThreads((Integer) threadsSpinner.getValue());
        p.setTimeout((Integer) timeoutSpinner.getValue());
        p.setMaxProbes((Integer) maxProbesSpinner.getValue());
        p.setMaxResults((Integer) maxResultsSpinner.getValue());
        p.setLogCap((Integer) logCapSpinner.getValue());
        p.setOobUrl(oobUrlField.getText().trim());
        p.setWordlist(wordlistField.getText().trim());
        p.save();
    }
}
