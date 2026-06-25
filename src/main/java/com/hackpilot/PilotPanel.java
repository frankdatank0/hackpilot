package com.hackpilot;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.text.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Main extension UI with agentic testing loop.
 *
 * Layout:
 *   Top:    Settings bar (API base, key, model)
 *   Left:   Session list
 *   Center: Analysis output + conversation
 *   Bottom: Action bar (prompt input + approve/skip/fire-all buttons)
 */
public class PilotPanel extends JPanel {

    private DefaultListModel<String> sessionListModel;
    private JList<String> sessionList;
    private JTextPane outputPane;
    private JTextField promptField;
    private JButton sendButton;
    private JButton exportButton;
    private JLabel statusLabel;

    // Agentic controls
    private JButton approveButton;
    private JButton skipButton;
    private JButton fireAllButton;
    private JButton stopButton;
    private JPanel agentControlPanel;

    // Settings fields
    private JTextField apiBaseField;
    private JTextField apiKeyField;
    private JTextField modelField;
    private JCheckBox tlsVerifyCheckbox;

    private final List<AnalysisSession> sessions = new ArrayList<>();
    private AnalysisSession activeSession = null;

    // Agentic state
    private List<TestProposal> pendingProposals = new ArrayList<>();
    private int currentProposalIndex = -1;
    private volatile boolean agentLoopRunning = false;
    private burp.api.montoya.http.message.requests.HttpRequest originalBurpRequest = null;
    private int consecutiveFailures = 0;
    private static final int MAX_CONSECUTIVE_FAILURES = 3;

    // Consecutive content-filter blocks from the LLM gateway. Distinct from
    // consecutiveFailures (which tracks HTTP send failures) — repeated guardrail
    // blocks mean the conversation context is the problem, so we halt and tell the
    // operator rather than spinning.
    private int consecutiveFilterBlocks = 0;
    private static final int MAX_FILTER_BLOCKS = 2;

    // Bounds on what we resend to the LLM each turn. Resending the full transcript
    // balloons tokens and, on a moderated gateway, repeatedly re-exposes the model's
    // own prior offensive analysis to the content filter (the root cause of the
    // finish_reason=content_filter blocks that appear after the first turn).
    private static final int LLM_MAX_ASSISTANT_CHARS = 1200;
    private static final int LLM_MAX_TAIL_MESSAGES = 8;

    private LlmClient llmClient;
    private BurpHttpSender httpSender;
    private final burp.api.montoya.logging.Logging logging;

    public PilotPanel(burp.api.montoya.logging.Logging logging) {
        this.logging = logging;
        setLayout(new BorderLayout(0, 0));

        JPanel settingsPanel = createSettingsPanel();
        add(settingsPanel, BorderLayout.NORTH);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setDividerLocation(260);
        mainSplit.setBorder(null);

        JPanel leftPanel = createSessionListPanel();
        mainSplit.setLeftComponent(leftPanel);

        JPanel rightPanel = createOutputPanel();
        mainSplit.setRightComponent(rightPanel);

        add(mainSplit, BorderLayout.CENTER);

        initClient();
    }

    public void setHttpSender(BurpHttpSender sender) {
        this.httpSender = sender;
    }

    // ─── Settings Panel ────────────────────────────────────────────────

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        panel.setBorder(new CompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UIManager.getColor("Separator.foreground")),
                new EmptyBorder(4, 8, 4, 8)
        ));

        panel.add(new JLabel("API Base:"));
        apiBaseField = new JTextField("https://api.anthropic.com", 22);
        panel.add(apiBaseField);

        panel.add(new JLabel("API Key:"));
        apiKeyField = new JTextField(20);
        panel.add(apiKeyField);

        panel.add(new JLabel("Model:"));
        modelField = new JTextField("claude-sonnet-4-20250514", 18);
        panel.add(modelField);

        tlsVerifyCheckbox = new JCheckBox("Verify TLS", true);
        tlsVerifyCheckbox.setToolTipText("Uncheck for internal servers with self-signed certs");
        panel.add(tlsVerifyCheckbox);

        JButton applyBtn = new JButton("Apply");
        applyBtn.addActionListener(e -> initClient());
        panel.add(applyBtn);

        return panel;
    }

    // ─── Session List ──────────────────────────────────────────────────

    private JPanel createSessionListPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(new EmptyBorder(8, 8, 8, 4));

        JLabel title = new JLabel("Analysis Sessions");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
        panel.add(title, BorderLayout.NORTH);

        sessionListModel = new DefaultListModel<>();
        sessionList = new JList<>(sessionListModel);
        sessionList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        sessionList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        sessionList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int idx = sessionList.getSelectedIndex();
                if (idx >= 0 && idx < sessions.size()) {
                    activeSession = sessions.get(idx);
                    renderSession(activeSession);
                }
            }
        });

        JScrollPane listScroll = new JScrollPane(sessionList);
        panel.add(listScroll, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        exportButton = new JButton("Export Session");
        exportButton.setEnabled(false);
        exportButton.addActionListener(e -> exportActiveSession());
        btnPanel.add(exportButton);

        JButton exportAllBtn = new JButton("Export All");
        exportAllBtn.addActionListener(e -> exportAllSessions());
        btnPanel.add(exportAllBtn);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> clearSessions());
        btnPanel.add(clearBtn);

        panel.add(btnPanel, BorderLayout.SOUTH);
        return panel;
    }

    // ─── Output Panel + Action Bar ─────────────────────────────────────

    private JPanel createOutputPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(new EmptyBorder(8, 4, 8, 8));

        outputPane = new JTextPane();
        outputPane.setEditable(false);
        outputPane.setContentType("text/plain");
        outputPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        outputPane.setText(
            "HackPilot v1.2 — Agentic Testing Mode\n"
          + "═══════════════════════════════════════════\n\n"
          + "Right-click a request in Proxy/Repeater/Logger\n"
          + "  -> Analyze with HackPilot\n\n"
          + "The model will analyze the request and PROPOSE tests.\n"
          + "You approve or skip each test. Approved tests fire through\n"
          + "Burp, and the model auto-analyzes the response and suggests\n"
          + "the next test.\n\n"
          + "You can also type follow-up context at any time:\n"
          + "  - Tenant B user IDs for IDOR testing\n"
          + "  - Admin tokens for privilege escalation\n"
          + "  - Additional endpoints to chain attacks\n"
        );

        JScrollPane outputScroll = new JScrollPane(outputPane);
        panel.add(outputScroll, BorderLayout.CENTER);

        // Bottom panel: status + prompt + agent controls
        JPanel bottomPanel = new JPanel(new BorderLayout(4, 4));

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        bottomPanel.add(statusLabel, BorderLayout.NORTH);

        // Prompt row
        JPanel promptRow = new JPanel(new BorderLayout(4, 0));
        promptField = new JTextField();
        promptField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        promptField.setToolTipText("Follow up with context, IDs, tokens — or just chat");
        promptField.addActionListener(e -> sendFollowUp());
        promptRow.add(promptField, BorderLayout.CENTER);

        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendFollowUp());
        promptRow.add(sendButton, BorderLayout.EAST);

        bottomPanel.add(promptRow, BorderLayout.CENTER);

        // Agent control buttons
        agentControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));

        approveButton = new JButton("Approve & Send");
        approveButton.setToolTipText("Send the current proposed test through Burp");
        approveButton.addActionListener(e -> approveCurrentProposal());
        approveButton.setEnabled(false);
        agentControlPanel.add(approveButton);

        skipButton = new JButton("Skip");
        skipButton.setToolTipText("Skip this test, move to the next proposal");
        skipButton.addActionListener(e -> skipCurrentProposal());
        skipButton.setEnabled(false);
        agentControlPanel.add(skipButton);

        fireAllButton = new JButton("Fire All");
        fireAllButton.setToolTipText("Send ALL pending tests automatically");
        fireAllButton.addActionListener(e -> fireAllProposals());
        fireAllButton.setEnabled(false);
        agentControlPanel.add(fireAllButton);

        stopButton = new JButton("Stop");
        stopButton.setToolTipText("Stop the agentic loop");
        stopButton.addActionListener(e -> stopAgentLoop());
        stopButton.setEnabled(false);
        agentControlPanel.add(stopButton);

        bottomPanel.add(agentControlPanel, BorderLayout.SOUTH);

        panel.add(bottomPanel, BorderLayout.SOUTH);
        return panel;
    }

    // ─── Public API ────────────────────────────────────────────────────

    public void analyzeRequest(String method, String url, String fullRequest,
                                String requestBody, String responseBody, int statusCode,
                                burp.api.montoya.http.message.requests.HttpRequest burpRequest) {
        AnalysisSession session = new AnalysisSession(method, url, fullRequest, requestBody, responseBody, statusCode);
        sessions.add(session);
        activeSession = session;
        originalBurpRequest = burpRequest;
        consecutiveFailures = 0;
        consecutiveFilterBlocks = 0;

        SwingUtilities.invokeLater(() -> {
            sessionListModel.addElement(session.getLabel());
            sessionList.setSelectedIndex(sessions.size() - 1);
            exportButton.setEnabled(true);
            setStatus("Analyzing " + method + " " + url + "...");
            outputPane.setText("");
            appendToOutput("═══════════════════════════════════════════════════════\n");
            appendToOutput("SESSION " + session.getId() + " | " + session.getTimestamp() + "\n");
            appendToOutput(method + " " + url + " -> " + statusCode + "\n");
            appendToOutput("═══════════════════════════════════════════════════════\n\n");
            appendToOutput("[Analyzing request and generating test proposals...]\n\n");
        });

        String initialPrompt = session.buildInitialPrompt();
        session.addUserMessage(initialPrompt);

        llmClient.chatAsync(Prompts.ANALYSIS_SYSTEM_PROMPT,
                        session.buildLlmHistory(LLM_MAX_ASSISTANT_CHARS, LLM_MAX_TAIL_MESSAGES))
                .thenAccept(response -> {
                    session.addAssistantMessage(response);
                    List<TestProposal> proposals = TestProposal.parseFromResponse(response);
                    SwingUtilities.invokeLater(() -> {
                        renderSession(session);
                        if (!proposals.isEmpty()) {
                            pendingProposals = proposals;
                            currentProposalIndex = 0;
                            showCurrentProposal();
                        } else {
                            setStatus("Analysis complete (no auto-tests proposed). Use prompt to request tests.");
                        }
                    });
                })
                .exceptionally(ex -> {
                    logging.logToError("HackPilot initial-analysis error: " + rootMessage(ex));
                    SwingUtilities.invokeLater(() -> {
                        appendToOutput("\n" + describeLlmError(ex) + "\n\n");
                        setStatus("Error during analysis");
                    });
                    return null;
                });
    }

    // ─── Agentic Loop ──────────────────────────────────────────────────

    private void showCurrentProposal() {
        if (currentProposalIndex < 0 || currentProposalIndex >= pendingProposals.size()) {
            setAgentControlsEnabled(false);
            setStatus("All proposed tests processed.");
            return;
        }

        TestProposal proposal = pendingProposals.get(currentProposalIndex);
        int total = pendingProposals.size();
        int current = currentProposalIndex + 1;

        appendToOutput("\n>>> PROPOSED TEST " + current + "/" + total + " <<<\n");
        appendToOutput("NAME:   " + proposal.getName() + "\n");
        appendToOutput("WHY:    " + proposal.getReasoning() + "\n");
        appendToOutput("CHANGE: " + proposal.getModType() + " " + proposal.getTarget()
                + " = " + proposal.getValue() + "\n\n");
        appendToOutput("  [Approve & Send]  [Skip]  [Fire All]  [Stop]\n\n");

        setAgentControlsEnabled(true);
        setStatus("Test " + current + "/" + total + " awaiting approval: " + proposal.getName());
    }

    private void approveCurrentProposal() {
        if (currentProposalIndex < 0 || currentProposalIndex >= pendingProposals.size()) return;
        if (httpSender == null || originalBurpRequest == null) {
            appendToOutput("[ERROR] HTTP sender or original request not available.\n");
            return;
        }

        TestProposal proposal = pendingProposals.get(currentProposalIndex);
        proposal.setStatus(TestProposal.Status.APPROVED);
        setAgentControlsEnabled(false);
        setStatus("Sending: " + proposal.getName() + "...");
        appendToOutput(">>> SENDING: " + proposal.getName() + "\n");
        appendToOutput("    MODIFY " + proposal.getModType() + ": "
                + proposal.getTarget() + " = " + proposal.getValue() + "\n");

        CompletableFuture.supplyAsync(() -> {
            return httpSender.sendModifiedRequest(originalBurpRequest, proposal);
        }).thenAccept(result -> {
            proposal.setResponse(result.statusCode, result.headers, result.body);
            proposal.setStatus(TestProposal.Status.SENT);

            // Circuit breaker: track consecutive failures
            if (result.statusCode == 0 || result.body.startsWith("ERROR")) {
                consecutiveFailures++;
            } else {
                consecutiveFailures = 0;
            }

            SwingUtilities.invokeLater(() -> {
                appendToOutput("<<< RESPONSE: " + result.statusCode + "\n");
                String bodySnippet = result.body;
                if (bodySnippet != null && bodySnippet.length() > 800) {
                    bodySnippet = bodySnippet.substring(0, 800) + "\n  [... truncated ...]";
                }
                if (bodySnippet != null && !bodySnippet.isBlank()) {
                    appendToOutput(bodySnippet + "\n");
                }
                appendToOutput("---\n\n");

                if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                    appendToOutput(">>> CIRCUIT BREAKER: " + consecutiveFailures
                            + " consecutive failures. Stopping agent loop.\n");
                    appendToOutput("    Check: proxy config, target availability, WAF/rate limiting.\n");
                    appendToOutput("    Use the prompt field to continue manually when ready.\n\n");
                    agentLoopRunning = false;
                    setAgentControlsEnabled(false);
                    setStatus("Stopped: " + consecutiveFailures + " consecutive failures");
                    return;
                }

                setStatus("Response received. Auto-analyzing...");
            });

            if (consecutiveFailures < MAX_CONSECUTIVE_FAILURES) {
                autoAnalyzeResult(proposal);
            }

        }).exceptionally(ex -> {
            SwingUtilities.invokeLater(() -> {
                appendToOutput("[ERROR sending] " + ex.getMessage() + "\n\n");
                advanceToNextProposal();
            });
            return null;
        });
    }

    private void autoAnalyzeResult(TestProposal proposal) {
        if (activeSession == null) return;

        String feedback = proposal.buildResultFeedback();
        String followUp = "I just sent the test: " + proposal.getName() + "\n\n"
                + feedback + "\n\n"
                + "Analyze this response. Did the test reveal a vulnerability? "
                + "What does the response tell us? "
                + "Based on this result, propose the next test to try. "
                + "Use the PROPOSE_TEST format if you have a concrete next test.";

        activeSession.addUserMessage(followUp);

        llmClient.chatAsync(Prompts.ANALYSIS_SYSTEM_PROMPT,
                        activeSession.buildLlmHistory(LLM_MAX_ASSISTANT_CHARS, LLM_MAX_TAIL_MESSAGES))
                .thenAccept(response -> {
                    proposal.setStatus(TestProposal.Status.ANALYZED);
                    activeSession.addAssistantMessage(response);
                    consecutiveFilterBlocks = 0;

                    // Parse any new proposals from the auto-analysis
                    List<TestProposal> newProposals = TestProposal.parseFromResponse(response);

                    SwingUtilities.invokeLater(() -> {
                        appendToOutput("[AUTO-ANALYSIS]\n");
                        appendToOutput(response + "\n");
                        appendToOutput("───────────────────────────────────────────────────────\n\n");

                        if (!newProposals.isEmpty()) {
                            // Append new proposals to the queue
                            for (TestProposal np : newProposals) {
                                pendingProposals.add(np);
                            }
                            appendToOutput("[" + newProposals.size() + " new test(s) proposed]\n\n");
                        }

                        advanceToNextProposal();
                    });
                })
                .exceptionally(ex -> {
                    LlmClient.LlmException le = asLlmException(ex);
                    boolean filtered = le != null && le.kind == LlmClient.LlmException.Kind.CONTENT_FILTER;
                    if (filtered) consecutiveFilterBlocks++; else consecutiveFilterBlocks = 0;
                    logging.logToError("HackPilot auto-analysis error: " + rootMessage(ex));
                    SwingUtilities.invokeLater(() -> {
                        appendToOutput(describeLlmError(ex) + "\n\n");
                        if (filtered && consecutiveFilterBlocks >= MAX_FILTER_BLOCKS) {
                            appendToOutput(">>> Auto-analysis halted: the gateway content-filtered "
                                    + consecutiveFilterBlocks + " turns in a row.\n"
                                    + "    Type 'reset' in the prompt to shrink the context, or relax your\n"
                                    + "    LiteLLM guardrail, then click Approve/Fire All to continue.\n\n");
                            setAgentControlsEnabled(false);
                            setStatus("Auto-analysis halted: repeated content-filter blocks");
                            return;
                        }
                        advanceToNextProposal();
                    });
                    return null;
                });
    }

    private void skipCurrentProposal() {
        if (currentProposalIndex < 0 || currentProposalIndex >= pendingProposals.size()) return;
        TestProposal proposal = pendingProposals.get(currentProposalIndex);
        proposal.setStatus(TestProposal.Status.SKIPPED);
        appendToOutput(">>> SKIPPED: " + proposal.getName() + "\n\n");
        advanceToNextProposal();
    }

    private void fireAllProposals() {
        if (httpSender == null) {
            appendToOutput("[ERROR] HTTP sender not initialized.\n");
            return;
        }
        agentLoopRunning = true;
        stopButton.setEnabled(true);
        fireAllButton.setEnabled(false);
        approveButton.setEnabled(false);
        skipButton.setEnabled(false);
        appendToOutput(">>> FIRING ALL REMAINING TESTS <<<\n\n");
        fireNextInBatch();
    }

    private void fireNextInBatch() {
        if (!agentLoopRunning) {
            appendToOutput(">>> Agent loop stopped by user.\n\n");
            setAgentControlsEnabled(false);
            stopButton.setEnabled(false);
            return;
        }

        // Find next pending proposal
        while (currentProposalIndex < pendingProposals.size()) {
            TestProposal p = pendingProposals.get(currentProposalIndex);
            if (p.getStatus() == TestProposal.Status.PENDING) {
                break;
            }
            currentProposalIndex++;
        }

        if (currentProposalIndex >= pendingProposals.size()) {
            appendToOutput(">>> All tests complete.\n\n");
            agentLoopRunning = false;
            setAgentControlsEnabled(false);
            stopButton.setEnabled(false);
            setStatus("Batch complete. " + pendingProposals.size() + " tests processed.");
            return;
        }

        TestProposal proposal = pendingProposals.get(currentProposalIndex);
        proposal.setStatus(TestProposal.Status.APPROVED);
        setStatus("Batch: sending " + proposal.getName() + "...");
        appendToOutput(">>> SENDING: " + proposal.getName()
                + " [" + proposal.getModType() + " " + proposal.getTarget()
                + " = " + proposal.getValue() + "]\n");

        CompletableFuture.supplyAsync(() -> {
            return httpSender.sendModifiedRequest(originalBurpRequest, proposal);
        }).thenAccept(result -> {
            proposal.setResponse(result.statusCode, result.headers, result.body);
            proposal.setStatus(TestProposal.Status.SENT);

            // Circuit breaker
            if (result.statusCode == 0 || result.body.startsWith("ERROR")) {
                consecutiveFailures++;
            } else {
                consecutiveFailures = 0;
            }

            SwingUtilities.invokeLater(() -> {
                appendToOutput("<<< RESPONSE: " + result.statusCode + "\n");

                if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                    appendToOutput(">>> CIRCUIT BREAKER: " + consecutiveFailures
                            + " consecutive failures. Halting batch.\n");
                    appendToOutput("    Likely cause: rate limiting, WAF block, or connection issue.\n");
                    appendToOutput("    Fix the issue, then use prompt or click Fire All to resume.\n\n");
                    agentLoopRunning = false;
                    setAgentControlsEnabled(false);
                    stopButton.setEnabled(false);
                    setStatus("Batch halted: " + consecutiveFailures + " consecutive failures");
                    return;
                }
                appendToOutput("───────────────────────────────────────────────────────\n");
            });

            // Auto-analyze, then continue the batch
            autoAnalyzeResultBatch(proposal);

        }).exceptionally(ex -> {
            SwingUtilities.invokeLater(() -> {
                appendToOutput("[ERROR] " + ex.getMessage() + "\n");
                currentProposalIndex++;
                fireNextInBatch();
            });
            return null;
        });
    }

    private void autoAnalyzeResultBatch(TestProposal proposal) {
        if (activeSession == null || !agentLoopRunning) return;

        String feedback = proposal.buildResultFeedback();
        String followUp = "Test executed: " + proposal.getName() + "\n\n"
                + feedback + "\n\n"
                + "Analyze this response briefly. Did it reveal a vulnerability? "
                + "Propose the next test using PROPOSE_TEST format if you have one.";

        activeSession.addUserMessage(followUp);

        llmClient.chatAsync(Prompts.ANALYSIS_SYSTEM_PROMPT,
                        activeSession.buildLlmHistory(LLM_MAX_ASSISTANT_CHARS, LLM_MAX_TAIL_MESSAGES))
                .thenAccept(response -> {
                    proposal.setStatus(TestProposal.Status.ANALYZED);
                    activeSession.addAssistantMessage(response);
                    consecutiveFilterBlocks = 0;

                    List<TestProposal> newProposals = TestProposal.parseFromResponse(response);

                    SwingUtilities.invokeLater(() -> {
                        appendToOutput("[ANALYSIS] " + proposal.getName() + ":\n");
                        // Show a compact version in batch mode
                        String compact = response.length() > 600
                                ? response.substring(0, 600) + "\n  [... see full session for details ...]"
                                : response;
                        appendToOutput(compact + "\n");
                        appendToOutput("───────────────────────────────────────────────────────\n\n");

                        if (!newProposals.isEmpty()) {
                            for (TestProposal np : newProposals) {
                                pendingProposals.add(np);
                            }
                        }

                        currentProposalIndex++;
                        fireNextInBatch();
                    });
                })
                .exceptionally(ex -> {
                    LlmClient.LlmException le = asLlmException(ex);
                    boolean filtered = le != null && le.kind == LlmClient.LlmException.Kind.CONTENT_FILTER;
                    if (filtered) consecutiveFilterBlocks++; else consecutiveFilterBlocks = 0;
                    logging.logToError("HackPilot batch auto-analysis error: " + rootMessage(ex));
                    SwingUtilities.invokeLater(() -> {
                        appendToOutput(describeLlmError(ex) + "\n\n");
                        if (filtered && consecutiveFilterBlocks >= MAX_FILTER_BLOCKS) {
                            appendToOutput(">>> Batch halted: the gateway content-filtered "
                                    + consecutiveFilterBlocks + " analyses in a row.\n"
                                    + "    Type 'reset' to shrink context, or relax the LiteLLM guardrail,\n"
                                    + "    then click Fire All to resume.\n\n");
                            agentLoopRunning = false;
                            setAgentControlsEnabled(false);
                            stopButton.setEnabled(false);
                            setStatus("Batch halted: repeated content-filter blocks");
                            return;
                        }
                        currentProposalIndex++;
                        fireNextInBatch();
                    });
                    return null;
                });
    }

    private void stopAgentLoop() {
        agentLoopRunning = false;
        stopButton.setEnabled(false);
        appendToOutput("\n>>> AGENT LOOP STOPPED BY USER <<<\n\n");
        setStatus("Stopped. Use prompt field to continue manually, or click Approve to resume.");
        // Re-enable single controls if there are pending proposals
        if (currentProposalIndex < pendingProposals.size()) {
            TestProposal current = pendingProposals.get(currentProposalIndex);
            if (current.getStatus() == TestProposal.Status.PENDING) {
                setAgentControlsEnabled(true);
            }
        }
    }

    private void advanceToNextProposal() {
        currentProposalIndex++;
        if (currentProposalIndex < pendingProposals.size()) {
            showCurrentProposal();
        } else {
            setAgentControlsEnabled(false);
            setStatus("All proposed tests processed. Send a follow-up for more.");
        }
    }

    private void setAgentControlsEnabled(boolean enabled) {
        approveButton.setEnabled(enabled);
        skipButton.setEnabled(enabled);
        fireAllButton.setEnabled(enabled);
    }

    // ─── Follow-up (manual chat) ───────────────────────────────────────

    private void sendFollowUp() {
        if (activeSession == null) {
            setStatus("No active session — analyze a request first");
            return;
        }
        String input = promptField.getText().trim();
        if (input.isEmpty()) return;

        // Operator escape hatch: drop the accumulated context that the gateway keeps
        // content-filtering, while keeping the original request/response grounding.
        if (input.equalsIgnoreCase("reset")) {
            promptField.setText("");
            activeSession.resetToGrounding();
            consecutiveFilterBlocks = 0;
            pendingProposals = new ArrayList<>();
            currentProposalIndex = -1;
            setAgentControlsEnabled(false);
            appendToOutput("\n>>> CONTEXT RESET — dropped follow-up history, kept the initial analysis.\n"
                    + "    Send your next message; the gateway should stop content-filtering now.\n\n");
            setStatus("Context reset to clear the gateway content filter.");
            return;
        }

        promptField.setText("");
        promptField.setEnabled(false);
        sendButton.setEnabled(false);
        setStatus("Sending follow-up...");

        activeSession.addUserMessage(input);
        appendToOutput("\n> YOU: " + input + "\n\n");

        llmClient.chatAsync(Prompts.ANALYSIS_SYSTEM_PROMPT,
                        activeSession.buildLlmHistory(LLM_MAX_ASSISTANT_CHARS, LLM_MAX_TAIL_MESSAGES))
                .thenAccept(response -> {
                    activeSession.addAssistantMessage(response);
                    consecutiveFilterBlocks = 0;
                    List<TestProposal> proposals = TestProposal.parseFromResponse(response);

                    SwingUtilities.invokeLater(() -> {
                        appendToOutput(response + "\n");
                        appendToOutput("───────────────────────────────────────────────────────\n\n");
                        promptField.setEnabled(true);
                        sendButton.setEnabled(true);
                        promptField.requestFocus();

                        if (!proposals.isEmpty()) {
                            pendingProposals = proposals;
                            currentProposalIndex = 0;
                            showCurrentProposal();
                            setStatus("Follow-up complete — " + proposals.size() + " test(s) proposed");
                        } else {
                            setStatus("Follow-up complete");
                        }
                    });
                })
                .exceptionally(ex -> {
                    logging.logToError("HackPilot follow-up error: " + rootMessage(ex));
                    SwingUtilities.invokeLater(() -> {
                        appendToOutput(describeLlmError(ex) + "\n\n");
                        promptField.setEnabled(true);
                        sendButton.setEnabled(true);
                        setStatus("Error during follow-up");
                    });
                    return null;
                });
    }

    // ─── Rendering ─────────────────────────────────────────────────────

    private void renderSession(AnalysisSession session) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════\n");
        sb.append("SESSION ").append(session.getId()).append(" | ").append(session.getTimestamp()).append("\n");
        sb.append(session.getMethod()).append(" ").append(session.getUrl()).append(" -> ").append(session.getStatusCode()).append("\n");
        sb.append("═══════════════════════════════════════════════════════\n\n");

        for (LlmClient.ChatMessage msg : session.getConversationHistory()) {
            if (msg.role.equals("user")) {
                if (msg.content.startsWith("Analyze this request") || msg.content.startsWith("Analyze the following")) {
                    sb.append("> [Initial request/response sent for analysis]\n\n");
                } else if (msg.content.startsWith("I just sent the test:") || msg.content.startsWith("Test executed:")) {
                    sb.append("> [Test result fed back for analysis]\n\n");
                } else {
                    sb.append("> YOU: ").append(msg.content).append("\n\n");
                }
            } else {
                sb.append(msg.content).append("\n\n");
                sb.append("───────────────────────────────────────────────────────\n\n");
            }
        }

        outputPane.setText(sb.toString());
        outputPane.setCaretPosition(outputPane.getDocument().getLength());
    }

    private void appendToOutput(String text) {
        try {
            Document doc = outputPane.getDocument();
            doc.insertString(doc.getLength(), text, null);
            outputPane.setCaretPosition(doc.getLength());
        } catch (BadLocationException ignored) {}
    }

    private void setStatus(String status) {
        statusLabel.setText(status);
    }

    // ─── LLM error helpers ─────────────────────────────────────────────

    /** Walks the cause chain (CompletionException -> RuntimeException -> ...) to find an LlmException. */
    private LlmClient.LlmException asLlmException(Throwable t) {
        Throwable cur = t;
        int guard = 0;
        while (cur != null && guard++ < 12) {
            if (cur instanceof LlmClient.LlmException) return (LlmClient.LlmException) cur;
            cur = cur.getCause();
        }
        return null;
    }

    /** Unwraps to the root cause for concise log lines. */
    private String rootMessage(Throwable t) {
        Throwable root = t;
        int guard = 0;
        while (root.getCause() != null && guard++ < 12) root = root.getCause();
        return root.getClass().getSimpleName() + ": " + root.getMessage();
    }

    /** Builds an operator-facing, actionable message for an LLM failure. */
    private String describeLlmError(Throwable ex) {
        LlmClient.LlmException le = asLlmException(ex);
        if (le != null && le.kind == LlmClient.LlmException.Kind.CONTENT_FILTER) {
            return "[CONTENT FILTER] " + le.getMessage() + "\n"
                 + "    Cause: the accumulated conversation is tripping your LiteLLM guardrail.\n"
                 + "    Fix:   type 'reset' to drop prior turns, Skip this test, or relax the\n"
                 + "           content-filter guardrail in your LiteLLM config for this model.";
        }
        if (le != null) {
            return "[LLM " + le.kind + "] " + le.getMessage();
        }
        return "[ERROR] " + rootMessage(ex);
    }

    // ─── Config ────────────────────────────────────────────────────────

    private void initClient() {
        String base = apiBaseField.getText().trim();
        String key = apiKeyField.getText().trim();
        String model = modelField.getText().trim();
        boolean tlsVerify = tlsVerifyCheckbox.isSelected();

        if (base.isEmpty()) base = "https://api.anthropic.com";
        if (model.isEmpty()) model = "claude-sonnet-4-20250514";

        if (llmClient != null) {
            llmClient.setApiBase(base);
            llmClient.setApiKey(key);
            llmClient.setModel(model);
            llmClient.setTlsVerify(tlsVerify);
        } else {
            llmClient = new LlmClient(base, key, model);
            llmClient.setTlsVerify(tlsVerify);
        }

        String fmt = llmClient.getFormat() == LlmClient.ApiFormat.ANTHROPIC_NATIVE ? "Anthropic" : "OpenAI-compat";
        String tlsStatus = tlsVerify ? "TLS verified" : "TLS verification DISABLED";
        setStatus("Configured: " + model + " @ " + base + " (" + fmt + ", " + tlsStatus + ")");
        logging.logToOutput("HackPilot configured: " + model + " via " + base + " [" + fmt + ", " + tlsStatus + "]");
    }

    // ─── Export ─────────────────────────────────────────────────────────

    private void exportActiveSession() {
        if (activeSession == null) return;
        String md = activeSession.exportMarkdown();
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("session_" + activeSession.getId() + ".md"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.writeString(chooser.getSelectedFile().toPath(), md);
                setStatus("Exported to " + chooser.getSelectedFile().getName());
            } catch (Exception ex) {
                setStatus("Export failed: " + ex.getMessage());
            }
        }
    }

    private void exportAllSessions() {
        if (sessions.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        sb.append("# HackPilot Engagement Log\n\n");
        for (AnalysisSession s : sessions) {
            sb.append(s.exportMarkdown()).append("\n\n");
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("hackpilot_log.md"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                java.nio.file.Files.writeString(chooser.getSelectedFile().toPath(), sb.toString());
                setStatus("Exported all sessions");
            } catch (Exception ex) {
                setStatus("Export failed: " + ex.getMessage());
            }
        }
    }

    private void clearSessions() {
        int result = JOptionPane.showConfirmDialog(this,
                "Clear all sessions? This cannot be undone.",
                "HackPilot", JOptionPane.YES_NO_OPTION);
        if (result == JOptionPane.YES_OPTION) {
            sessions.clear();
            sessionListModel.clear();
            activeSession = null;
            pendingProposals.clear();
            currentProposalIndex = -1;
            agentLoopRunning = false;
            outputPane.setText("");
            exportButton.setEnabled(false);
            setAgentControlsEnabled(false);
            setStatus("Sessions cleared");
        }
    }

    public void shutdown() {
        agentLoopRunning = false;
        if (llmClient != null) llmClient.shutdown();
    }
}
