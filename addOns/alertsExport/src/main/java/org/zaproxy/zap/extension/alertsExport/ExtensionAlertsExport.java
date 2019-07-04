/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertsexport;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.extension.report.ReportLastScan;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.spider.SpiderEventPublisher;

/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionAlertsExport extends ExtensionAdaptor
        implements CommandLineListener, EventConsumer {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAlertsExport";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "alertsExport";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final String AUTHOR = "Cloudanix";

    private static final Logger LOGGER = Logger.getLogger(ExtensionAlertsExport.class);

    private CommandLineArgument[] arguments = new CommandLineArgument[1];
    private static final int ARG_ALERTS_EXPORT_URL_IDX = 0;

    private String TargetURL = "";

    public ExtensionAlertsExport() {
        super(NAME);
        this.setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();

        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        AlertEventPublisher.getPublisher().getPublisherName(),
                        new String[] {AlertEventPublisher.ALERT_ADDED_EVENT});

        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        SpiderEventPublisher.getPublisher().getPublisherName(),
                        new String[] {SpiderEventPublisher.SCAN_COMPLETED_EVENT});
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        LOGGER.info("alertsExport add-on is loading. inside hook method");

        // As long as we're not running as a daemon
        if (getView() != null) {}

        extensionHook.addCommandLine(getCommandLineArguments());
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).

        ZAP.getEventBus()
                .unregisterConsumer(this, AlertEventPublisher.getPublisher().getPublisherName());

        ZAP.getEventBus()
                .unregisterConsumer(this, SpiderEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public String getAuthor() {
        return AUTHOR;
    }

    @Override
    public String getDescription() {
        return this.getMessages().getString(PREFIX + ".desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_EXTENSIONS_PAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_ALERTS_EXPORT_URL_IDX].isEnabled()) {
            String targetPath = arguments[ARG_ALERTS_EXPORT_URL_IDX].getArguments().get(0);

            TargetURL = targetPath;
            LOGGER.info("targetPath from commandline: " + targetPath);
            LOGGER.info("TargetURL: " + TargetURL);
        } else {
            return;
        }
    }

    @Override
    public List<String> getHandledExtensions() {
        return null;
    }

    @Override
    public boolean handleFile(File file) {
        // Not supported
        return false;
    }

    private String getScanReport() throws Exception {
        ReportLastScan report = new ReportLastScan();
        StringBuilder rpt = new StringBuilder();
        report.generate(rpt, getModel());
        return rpt.toString();
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_ALERTS_EXPORT_URL_IDX] =
                new CommandLineArgument(
                        "-alertsexporturl",
                        1,
                        null,
                        "",
                        "-alertsexporturl [target url]: "
                                + Constant.messages.getString("alertsexport.cmdline.url.help"));
        return arguments;
    }

    @Override
    public void eventReceived(Event event) {
        LOGGER.info("event type: " + event.getEventType());

        switch (event.getEventType()) {
            case SpiderEventPublisher.SCAN_COMPLETED_EVENT:
                LOGGER.info(
                        "scan completed: "
                                + event.getParameters().get(SpiderEventPublisher.SCAN_ID));

                // LOGGER.info("TargetURL: " + TargetURL);

                try {
                    String report = getScanReport();

                    String jsonReport = ReportGenerator.stringToJson(report.toString());

                    LOGGER.info("last scan report: " + jsonReport);

                    PostReport(jsonReport, TargetURL);

                } catch (Exception e) {
                    LOGGER.error("exception while getting last scan report: " + e);
                }

                break;
            case AlertEventPublisher.ALERT_ADDED_EVENT:
                TableAlert tableAlert = Model.getSingleton().getDb().getTableAlert();

                String alertId = event.getParameters().get(AlertEventPublisher.ALERT_ID);

                LOGGER.info("alertId: " + alertId);

                // LOGGER.info("TargetURL: " + TargetURL);

                break;
        }
    }

    public void PostReport(String report, String target) throws IOException {
        CloseableHttpClient client = HttpClients.createDefault();

        try {
            HttpPost httpPost = new HttpPost(target);

            StringEntity entity = new StringEntity(report);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            CloseableHttpResponse response = client.execute(httpPost);
            HttpEntity resEntity = response.getEntity();

            if (resEntity != null) {
                EntityUtils.consume(resEntity);
            }

            StatusLine responseLine = null;
            int responseCode = -1;
            if (response != null) {
                responseLine = response.getStatusLine();
                responseCode = responseLine.getStatusCode();
            }

            LOGGER.info("response status line: " + responseLine);

            LOGGER.info("response status code: " + responseCode);

            LOGGER.info("response from HTTP Post: " + resEntity.toString());
        } finally {
            client.close();
        }
    }
}
