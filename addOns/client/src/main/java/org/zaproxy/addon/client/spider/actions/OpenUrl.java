/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.client.spider.actions;

import java.util.Objects;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.zap.utils.Stats;

public class OpenUrl implements SpiderAction {

    private static final String STATS_PREFIX = "stats.client.spider.action.url";

    private final String url;

    public OpenUrl(String url) {
        this.url = Objects.requireNonNull(url);
    }

    @Override
    public void run(WebDriver wd) {
        Stats.incCounter(STATS_PREFIX);
        wd.get(url);
    }
}
