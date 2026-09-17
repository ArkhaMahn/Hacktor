package org.zaproxy.zap.extension.hacktor;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/**
 * Right-click popup menu item "Send to Hacktor".
 * Appears in the Sites tree, History, and Search panels.
 */
public class PopupMenuSendToBypass extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private final ExtensionHacktor extension;

    public PopupMenuSendToBypass(ExtensionHacktor extension) {
        super("Send to Hacktor");
        this.extension = extension;
    }

    @Override
    protected void performAction(HttpMessage message) {
        if (message != null) {
            extension.sendToPanel(message.cloneRequest());
        }
    }

    @Override
    protected boolean isEnableForInvoker(
            Invoker invoker,
            HttpMessageContainer httpMessageContainer) {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    @Override
    public int getWeight() {
        return 25070;
    }
}
