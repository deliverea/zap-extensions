package org.zaproxy.zap.extension.accessControl.automation;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;

import java.util.List;

public class ExtensionAccessControlAutomation  extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAccessControlAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAutomation.class);

    private AccessControlJob job;

    public ExtensionAccessControlAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        job = new AccessControlJob();
        extAuto.registerAutomationJob(job);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionAutomation extAuto =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);

        extAuto.unregisterAutomationJob(job);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("accessControl.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("accessControl.automation.name");
    }
}
