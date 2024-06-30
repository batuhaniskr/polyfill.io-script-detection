package com.batuhaniskr.polyfilldetection;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;

import java.util.regex.Pattern;

public class PolyfillCheck implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    String url = "";
    private SiteMap siteMap;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.siteMap = api.siteMap();
        api.extension().setName("Polyfill Detection");
        api.logging().logToOutput("Loaded Polyfill Detection extension");
        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        url = httpRequestToBeSent.url();
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        String body = httpResponseReceived.bodyToString();

        if (isPolyfillJs(body)) {
            addScanIssue(url);
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    private boolean isPolyfillJs(String body) {
        return Pattern.compile("http[s]?://.*polyfill\\.io/.*", Pattern.CASE_INSENSITIVE).matcher(body).find();
    }

    private void addScanIssue(String url) {
        siteMap.add(AuditIssue.auditIssue(
                "Detected Script from Malicious polyfill.io",
                "This is not associated with the polyfill.js library and is known to serve malicious content. polyfill.io javascript cdn service were compromised and used to serve malicious content.",
                "Remove polyfill.io cdn usage. Consider hosting polyfill.js locally if possible to reduce reliance on third-party CDNs.",
                url,
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.FIRM,
                "The application is using polyfill.js from a CDN. This could potentially expose the application to risks if the CDN is compromised.",
                "Consider hosting polyfill.js locally if possible to reduce reliance on third-party CDNs.",
                AuditIssueSeverity.HIGH
        ));

        api.logging().logToOutput("Detected Script from Malicious polyfill.io in " + url);
    }
}