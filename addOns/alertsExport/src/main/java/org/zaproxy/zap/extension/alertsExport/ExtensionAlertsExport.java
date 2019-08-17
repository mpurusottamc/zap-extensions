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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
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
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.extension.report.ReportLastScan;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.extension.params.HtmlParameterStats;
import org.zaproxy.zap.extension.params.SiteParameters;
import org.zaproxy.zap.extension.spider.SpiderEventPublisher;
import org.zaproxy.zap.view.ScanPanel;

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
    // protected static final String PREFIX = "alertsExport";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private static final Logger LOGGER = Logger.getLogger(ExtensionAlertsExport.class);

    private CommandLineArgument[] arguments = new CommandLineArgument[1];
    private static final int ARG_ALERTS_EXPORT_URL_IDX = 0;

    // This is the Owasp Result Push Message Listener URL
    private String ListenerURI = "";

    public ExtensionAlertsExport() {
        super(NAME);
        // this.setI18nPrefix(PREFIX);
    }

    @Override
    public void init() {
        super.init();

        ZAP.getEventBus()
                .registerConsumer(
                        this,
                        SpiderEventPublisher.getPublisher().getPublisherName(),
                        new String[] {SpiderEventPublisher.SCAN_COMPLETED_EVENT});

        // ZAP.getEventBus()
        //         .registerConsumer(
        //                 this,
        //                 AlertEventPublisher.getPublisher().getPublisherName(),
        //                 new String[] {AlertEventPublisher.ALERT_ADDED_EVENT});
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
                .unregisterConsumer(this, SpiderEventPublisher.getPublisher().getPublisherName());

        // ZAP.getEventBus()
        //         .unregisterConsumer(this, AlertEventPublisher.getPublisher().getPublisherName());
    }

    @Override
    public String getAuthor() {
        return Constant.messages.getString("alertsExport.author");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("alertsExport.desc");
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

            ListenerURI = targetPath;
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

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_ALERTS_EXPORT_URL_IDX] =
                new CommandLineArgument(
                        "-alertsexporturl",
                        1,
                        null,
                        "",
                        "-alertsexporturl [target url]: "
                                + Constant.messages.getString("alertsExport.cmdline.url.help"));
        return arguments;
    }

    @Override
    public void eventReceived(Event event) {
        LOGGER.info("received new event: " + event.getEventType());

        switch (event.getEventType()) {
            case SpiderEventPublisher.SCAN_COMPLETED_EVENT:
                String scanId = event.getParameters().get(SpiderEventPublisher.SCAN_ID);
                LOGGER.info("scan completed: " + scanId);

                try {
                    String report = getScanReport();

                    String jsonReport = ReportGenerator.stringToJson(report);

                    // embed ScanId into the report
                    jsonReport = "{\"@scanId\": \"" + scanId + "\"," + jsonReport.substring(1);

                    // LOGGER.info("Last Scan Report: " + jsonReport);

                    PostReport(jsonReport, ListenerURI);
                } catch (Exception e) {
                    LOGGER.error("exception while getting last scan report: " + e);
                }

                break;
                // case AlertEventPublisher.ALERT_ADDED_EVENT:
                //     String alertId = event.getParameters().get(AlertEventPublisher.ALERT_ID);

                //     LOGGER.info("alertId: " + alertId);

                //     //                     TableAlert tableAlert =
                //     // Model.getSingleton().getDb().getTableAlert();

                //     //                     RecordAlert recordAlert;
                //     //                     try {
                //     //                         recordAlert = tableAlert.read(0);
                //     //
                //     //                         int historyId = recordAlert.getHistoryId();
                //     //
                //     //                         LOGGER.info("historyId: " + historyId);
                //     //
                //     ////                         TableHistory th =
                //     // Model.getSingleton().getDb().getTableHistory();
                //     ////                         RecordHistory rh = th.read(historyId);
                //     //
                //     //                     } catch (DatabaseException e) {
                //     //                         LOGGER.error("Failed to read the alert from the
                //     // session:", e);
                //     //                     } catch (Exception e) {
                //     //                         LOGGER.error("Failed to read the alert from the
                //     // session:", e);
                //     //                     }
                //     break;
        }
    }

    // import org.parosproxy.paros.db.DatabaseException;
    // import org.parosproxy.paros.db.RecordAlert;
    // import org.parosproxy.paros.db.RecordHistory;
    // import org.parosproxy.paros.db.TableAlert;
    // import org.parosproxy.paros.db.TableHistory;
    // import org.parosproxy.paros.model.Model;
    // import org.zaproxy.zap.extension.alert.AlertEventPublisher;

    private void printSiteTree(String scanId) {
        List<ScanUri> uris = getSiteURI();

        for (int i = 0; i < uris.size(); i++) {
            ScanUri uri = uris.get(i);
            LOGGER.info(
                    "scan info: "
                            + scanId
                            + " Name - "
                            + uri.Name()
                            + " Host - "
                            + uri.Host()
                            + " Port - "
                            + uri.Port()
                            + " IsSSL -  "
                            + uri.IsSSL());

            ExtensionParams params = new ExtensionParams();
            SiteParameters sps = params.getSiteParameters(uri.Host());
            List<HtmlParameterStats> lhps = sps.getParams(HtmlParameter.Type.url);

            LOGGER.info("parameters size: " + lhps.size());

            for (int j = 0; j < lhps.size(); j++) {
                HtmlParameterStats hps = lhps.get(i);

                Set<String> values = hps.getValues();

                for (Iterator<String> it = values.iterator(); it.hasNext(); ) {
                    String val = it.next();
                    LOGGER.info("values : " + val);
                }
            }
        }
    }

    public List<ScanUri> getSiteURI() {
        List<ScanUri> URIs = new ArrayList<>();
        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = siteMap.getRoot();
        int siteNumber = root.getChildCount();
        for (int i = 0; i < siteNumber; i++) {
            SiteNode site = (SiteNode) root.getChildAt(i);
            String siteName = ScanPanel.cleanSiteName(site, true);
            String[] hostAndPort = siteName.split(":");
            boolean isSSL = (site.getNodeName().startsWith("https"));
            URIs.add(new ScanUri(site.getNodeName(), hostAndPort[0], hostAndPort[1], isSSL));
        }

        return URIs;
    }

    private String getScanReport() throws Exception {
        ReportLastScan report = new ReportLastScan();
        StringBuilder rpt = new StringBuilder();
        report.generate(rpt, getModel());
        return rpt.toString();
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

            // LOGGER.info("response status line: " + responseLine);

            LOGGER.info(
                    "Scan Report posted. Content Length: ### "
                            + report.length()
                            + " ###. Response Status Code: ### "
                            + responseCode
                            + " ###. Target: ### "
                            + target
                            + " ###.");

            // LOGGER.info("response from HTTP Post: " + resEntity.toString());
        } finally {
            client.close();
        }
    }
}

class ScanUri {
    private String name;
    private String host;
    private String port;
    private Boolean isSSL;

    public ScanUri(String name, String host, String port, Boolean isSSL) {
        this.name = name;
        this.host = host;
        this.port = port;
        this.isSSL = isSSL;
    }

    public String Name() {
        return this.name;
    }

    public String Host() {
        return this.host;
    }

    public String Port() {
        return this.port;
    }

    public Boolean IsSSL() {
        return this.isSSL;
    }
}
