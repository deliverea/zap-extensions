package org.zaproxy.zap.extension.accessControl.automation;

import lombok.Getter;
import org.zaproxy.addon.automation.AutomationData;

import java.util.List;

@Getter
public class AccessRule extends AutomationData {
    private String uri;
    List<String> methods;
    private String access;

    public AccessRule() {}

    public AccessRule(String uri, List<String> methods, String access) {
        this.uri = uri;
        this.methods = methods;
        this.access = access;
    }
}
