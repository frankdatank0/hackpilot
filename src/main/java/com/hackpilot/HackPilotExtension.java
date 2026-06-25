package com.hackpilot;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * HackPilot — AI-powered request analysis for Burp Suite.
 *
 * Right-click any request → "Analyze with HackPilot" → get vulnerability
 * analysis, suggested payloads, and a conversational follow-up interface
 * for testing IDOR, RBAC, and other access control issues.
 *
 * Supports any OpenAI-compatible LLM backend (Anthropic, OpenAI, Ollama, etc.)
 */
public class HackPilotExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "HackPilot";
    private MontoyaApi api;
    private PilotPanel panel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);

        // Create the main UI panel
        panel = new PilotPanel(api.logging());

        // Wire up the HTTP sender so the panel can fire requests through Burp
        panel.setHttpSender(new BurpHttpSender(api));

        // Register as a Burp Suite tab
        api.userInterface().registerSuiteTab(EXTENSION_NAME, panel);

        // Register context menu item on all tools
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();

                // Only show when there's a request to analyze
                List<HttpRequestResponse> selected = event.selectedRequestResponses();
                if (selected == null || selected.isEmpty()) {
                    // Try message editor request
                    if (event.messageEditorRequestResponse().isPresent()) {
                        HttpRequestResponse reqRes = event.messageEditorRequestResponse().get().requestResponse();
                        JMenuItem item = createMenuItem(reqRes);
                        if (item != null) items.add(item);
                    }
                    return items;
                }

                // Single selection: direct analyze
                if (selected.size() == 1) {
                    JMenuItem item = createMenuItem(selected.get(0));
                    if (item != null) items.add(item);
                } else {
                    // Multiple selection: analyze each
                    JMenu menu = new JMenu("Analyze with " + EXTENSION_NAME);
                    for (int i = 0; i < Math.min(selected.size(), 10); i++) {
                        HttpRequestResponse rr = selected.get(i);
                        HttpRequest req = rr.request();
                        String label = req.method() + " " + truncatePath(req.url(), 60);
                        JMenuItem sub = new JMenuItem(label);
                        sub.addActionListener(e -> analyzeRequestResponse(rr));
                        menu.add(sub);
                    }
                    if (selected.size() > 10) {
                        menu.addSeparator();
                        menu.add(new JMenuItem("(" + (selected.size() - 10) + " more not shown)"));
                    }
                    items.add(menu);
                }

                return items;
            }
        });

        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            if (panel != null) panel.shutdown();
        });

        api.logging().logToOutput(EXTENSION_NAME + " v1.0.0 loaded successfully.");
        api.logging().logToOutput("Configure your API key in the " + EXTENSION_NAME + " tab, then right-click any request to analyze.");
    }

    private JMenuItem createMenuItem(HttpRequestResponse reqRes) {
        if (reqRes == null || reqRes.request() == null) return null;

        HttpRequest req = reqRes.request();
        String label = "Analyze with " + EXTENSION_NAME + " — "
                + req.method() + " " + truncatePath(req.url(), 50);

        JMenuItem item = new JMenuItem(label);
        item.addActionListener(e -> analyzeRequestResponse(reqRes));
        return item;
    }

    private void analyzeRequestResponse(HttpRequestResponse reqRes) {
        HttpRequest req = reqRes.request();
        HttpResponse res = reqRes.response();

        String method = req.method();
        String url = req.url();
        String fullRequest = req.toString();
        String requestBody = req.bodyToString();
        String responseBody = res != null ? res.bodyToString() : "(no response)";
        int statusCode = res != null ? res.statusCode() : 0;

        // Pass the original HttpRequest object so the agent can modify and resend it
        panel.analyzeRequest(method, url, fullRequest, requestBody, responseBody, statusCode, req);
    }

    private String truncatePath(String url, int maxLen) {
        if (url == null) return "";
        if (url.length() <= maxLen) return url;
        return url.substring(0, maxLen - 3) + "...";
    }
}
