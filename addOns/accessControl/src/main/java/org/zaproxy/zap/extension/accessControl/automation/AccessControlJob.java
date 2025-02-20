package org.zaproxy.zap.extension.accessControl.automation;

import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread;
import org.zaproxy.zap.extension.accessControl.ContextAccessRulesManager;
import org.zaproxy.zap.extension.accessControl.ExtensionAccessControl;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;
import org.zaproxy.zap.users.User;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class AccessControlJob extends AutomationJob {
    private static final String JOB_NAME = "accessControl";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_REPORT_FILE = "reportFile";
    private static final String PARAM_SCAN_AS_UN_AUTH_USER = "scanAsUnAuthUser";

    private static final String UN_AUTH_USER_NAME = "unAuthUser";

    private ExtensionAccessControl extAccessControl;

    private Parameters parameters = new Parameters();
    private Map<String, List<AccessRule>> accessRules = new HashMap<>();
    private Data data;

    public AccessControlJob() {
        this.data = new Data(this, parameters, this.accessRules);
    }

    private ExtensionAccessControl getExtAccessControl() {
        if (extAccessControl == null) {
            extAccessControl =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAccessControl.class);
        }
        return extAccessControl;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }

        for (Object key : jobData.keySet().toArray()) {
            switch (key.toString()) {
                case "parameters":
                    LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get(key);
                    JobUtils.applyParamsToObject(
                            params, this.parameters, this.getName(), null, progress);
                    break;
                case "accessRules":
                case "type":
                    // Handled before we get here
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.element.unknown", this.getName(), key));

                    break;
            }
        }

        var accessRulesObject = jobData.get("accessRules");

        if (accessRulesObject == null) {
            progress.warn(
                Constant.messages.getString("accessControl.automation.warn.accessRules.undefined", this.getName())
            );
            return;
        }

        if (accessRulesObject instanceof LinkedHashMap<?,?>) {
            @SuppressWarnings("unchecked")
            LinkedHashMap<Object, Object> accessRulesData = (LinkedHashMap<Object, Object>) accessRulesObject;

            accessRulesData.forEach((key, value) -> {
                String userName = key.toString();
                List<AccessRule> userAccessRules = new ArrayList<>();

                if (value instanceof ArrayList<?> rulesData) {
                    for (Object ruleData : rulesData) {
                        if (ruleData instanceof LinkedHashMap<?, ?> ruleMap) {
                            String nodeName = ruleMap.get("uri") != null
                                    ? getEnv().replaceVars(ruleMap.get("uri"))
                                    : ".*";

                            @SuppressWarnings("unchecked")
                            ArrayList<String> methods = (ArrayList<String>) ruleMap.get("methods");
                            String access = (String) ruleMap.get("access");

                            if (methods == null) {
                                methods = new ArrayList<>();
                            }

                            if (methods.isEmpty()) {
                                methods.addAll(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE"));
                            }

                            userAccessRules.add(new AccessRule(nodeName, methods, access));
                        }
                    }
                }

                this.accessRules.put(userName, userAccessRules);
            });
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {PARAM_CONTEXT, PARAM_REPORT_FILE},
                progress,
                this.getPlan().getEnv());
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        map.put(PARAM_REPORT_FILE, "");
        map.put(
            PARAM_SCAN_AS_UN_AUTH_USER,
            Boolean.toString(JobUtils.unBox(this.getParameters().getScanAsUnAuthUser()))
        );
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        var contextWrapper = env.getContextWrapper(getParameters().getContext());
        if (contextWrapper == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.unknown", getParameters().getContext()));
            return;
        }

        var targetNodes = Model.getSingleton()
                .getSession()
                .getNodesInContextFromSiteTree(contextWrapper.getContext());

        ContextAccessRulesManager accessRulesManager = getExtAccessControl().getContextAccessRulesManager(contextWrapper.getContext());
        accessRulesManager.reloadContextSiteTree(Model.getSingleton().getSession());

        progress.info("Available target nodes:");
        targetNodes.forEach(tn -> progress.info(tn.getNodeName() + " | " + tn.getHistoryReference().getMethod()+ " | " + tn.getHistoryReference().getURI().toString()));

        for (var userAccessRules : getData().getAccessRules().entrySet()) {
            var userId = userAccessRules.getKey().equals(UN_AUTH_USER_NAME)
                    ? ContextAccessRulesManager.UNAUTHENTICATED_USER_ID :
                    contextWrapper.getUser(userAccessRules.getKey()).getId();

            for (var accessRule : userAccessRules.getValue()) {
                var nodes = targetNodes.stream().filter(sn -> sn.getHistoryReference().getURI().toString().matches(accessRule.getUri())
                        && accessRule.methods.contains(sn.getHistoryReference().getMethod())).toList();

                if (nodes.isEmpty()) {
                    progress.warn(
                            String.format(
                                    "Unable to find node of URI %s with methods %s",
                                    accessRule.getUri(),
                                    accessRule.methods
                            )
                    );
                    continue;
                }

                nodes.forEach(node -> {
                    progress.info(
                            String.format(
                                    "Adding rule %s in %s for user %s",
                                    accessRule.getAccess(),
                                    node.getNodeName(),
                                    userId
                            )
                    );

                    accessRulesManager.addRule(
                            userId,
                            new SiteTreeNode(node.getNodeName(), node.getHistoryReference().getURI()),
                            org.zaproxy.zap.extension.accessControl.AccessRule.valueOf(accessRule.getAccess())
                    );
                });
            }
        }

        List<User> users = new java.util.ArrayList<>(contextWrapper.getUserNames()
                .stream()
                .map(contextWrapper::getUser)
                .toList());

        if (getParameters().getScanAsUnAuthUser()) {
            users.add(null);
        }

        AccessControlScannerThread.AccessControlScanStartOptions options = new AccessControlScannerThread.AccessControlScanStartOptions();
        options.setTargetContext(contextWrapper.getContext());
        options.setTargetUsers(users);

        getExtAccessControl().startScan(options);

        progress.info(Constant.messages.getString("accessControl.automation.scan.started"));

        int contextId = contextWrapper.getContext().getId();
        int scanProgress = 0;
        String status = getExtAccessControl().getScanStatus(contextId);

        while (scanProgress < 100) {
            this.sleep(500);

            scanProgress = getExtAccessControl().getScanProgress(contextId);
            status = getExtAccessControl().getScanStatus(contextId);
        }

        if (status.equals("INTERRUPTED")) {
            progress.warn(Constant.messages.getString("accessControl.automation.scan.interrupted"));
            return;
        }

        progress.info(Constant.messages.getString("accessControl.automation.scan.finished"));

        File reportFile = new File(env.replaceVars(getParameters().getReportFile()));

        try {
            getExtAccessControl().generateAccessControlReport(contextId, reportFile);

            progress.info(Constant.messages.getString("accessControl.automation.report.generated"));
        } catch (ParserConfigurationException e) {
            progress.error(Constant.messages.getString("accessControl.automation.report.failed") + e.getMessage());
        }
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.ATTACK;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public Data getData() {
        return data;
    }

    @Getter
    @Setter
    public static class Data extends JobData {
        private Parameters parameters;
        private Map<String, List<AccessRule>> accessRules;

        public Data(AutomationJob job, Parameters parameters, Map<String, List<AccessRule>> rules) {
            super(job);

            this.parameters = parameters;
            this.accessRules = rules;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String context = "";
        private String reportFile = "";
        private Boolean scanAsUnAuthUser = false;
    }
}
