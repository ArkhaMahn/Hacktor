package org.zaproxy.zap.extension.hacktor;

import javax.swing.JMenuItem;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;

/**
 * ZAP extension entry point for the Hacktor addon.
 * Registers the work panel, Tools menu entry, and Sites tree popup menu.
 */
public class ExtensionHacktor extends ExtensionAdaptor {

    private static final String NAME = "ExtensionHacktor";
    private HacktorPanel panel;

    public ExtensionHacktor() {
        super(NAME);
    }

    @Override
    public String getUIName() {
        return "Hacktor";
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            panel = new HacktorPanel(this);
            ExtensionHookView hookView = extensionHook.getHookView();
            hookView.addWorkPanel(panel);

            // Tools menu item
            JMenuItem menuItem = new JMenuItem("Hacktor\u2026");
            menuItem.addActionListener(e -> selectWorkPanel());
            extensionHook.getHookMenu().addToolsMenuItem(menuItem);

            // Sites tree popup menu: "Send to Hacktor"
            extensionHook.getHookMenu().addPopupMenuItem(
                new PopupMenuSendToBypass(this));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (panel != null) {
            panel.unload();
        }
        super.unload();
    }

    @Override
    public String getDescription() {
        return "HTTP request tampering and fuzzing lab: 7800+ techniques across 40+ families "
            + "for access-control bypass, auth/authz probing, HTTP smuggling, cache poisoning, "
            + "injection probing, and OAuth 1.0a/2.0/OIDC tampering.";
    }

    @Override
    public void destroy() {
        if (panel != null) {
            panel.unload();
        }
        super.destroy();
    }

    HacktorPanel getPanel() {
        return panel;
    }

    void sendToPanel(org.parosproxy.paros.network.HttpMessage msg) {
        if (panel != null && msg != null) {
            try {
                panel.setBaseMessage(msg);
                selectWorkPanel();
                System.out.println("[Hacktor] sendToPanel: OK, URL=" + msg.getRequestHeader().getURI());
            } catch (Exception ex) {
                System.err.println("[Hacktor] sendToPanel failed: " + ex.getMessage());
                ex.printStackTrace();
            }
        } else {
            System.err.println("[Hacktor] sendToPanel: panel=" + panel + " msg=" + msg);
        }
    }

    private void selectWorkPanel() {
        try {
            if (panel != null && getView() != null && getView().getMainFrame() != null) {
                getView().getMainFrame().getWorkbench().getTabbedWork().setSelectedComponent(panel);
            }
        } catch (Exception ignored) {
        }
    }
}
