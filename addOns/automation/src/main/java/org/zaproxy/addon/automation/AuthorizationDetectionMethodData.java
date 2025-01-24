package org.zaproxy.addon.automation;

import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.authorization.BasicAuthorizationDetectionMethod;
import org.zaproxy.zap.model.Context;

import java.util.LinkedHashMap;

@Getter
@Setter
public class AuthorizationDetectionMethodData extends AutomationData {
    private int statusCode = BasicAuthorizationDetectionMethod.NO_STATUS_CODE;
    private String headerRegex;
    private String bodyRegex;
    private String logicalOperator;

    public AuthorizationDetectionMethodData() {}

    public AuthorizationDetectionMethodData(Object data, AutomationProgress progress) {
        if (!(data instanceof LinkedHashMap)) {
            progress.error(
                    Constant.messages.getString("automation.error.env.badauthorizationdetectionmethod", data));
        } else {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) data, this, "authorizationDetectionMethod", null, progress);
        }
    }

    public void initContextAuthorizationDetectionMethod(Context context, AutomationProgress progress, AutomationEnvironment env) {
        context.setAuthorizationDetectionMethod(
                new BasicAuthorizationDetectionMethod(
                        this.statusCode,
                        this.headerRegex,
                        this.bodyRegex,
                        this.logicalOperator != null
                                ? BasicAuthorizationDetectionMethod.LogicalOperator.valueOf(this.logicalOperator)
                                : BasicAuthorizationDetectionMethod.LogicalOperator.AND
                )
        );
    }
}
