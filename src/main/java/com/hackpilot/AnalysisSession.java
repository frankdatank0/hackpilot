package com.hackpilot;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single analysis session — one request/response pair plus
 * all follow-up conversation (IDOR context, RBAC IDs, etc.).
 * Each session becomes an entry in the accumulated log.
 */
public class AnalysisSession {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final String id;
    private final String timestamp;
    private final String method;
    private final String url;
    private final String fullRequest;
    private final String requestBody;
    private final String responseSnippet;
    private final int statusCode;
    private final List<LlmClient.ChatMessage> conversationHistory;
    private final List<String> analysisLog;

    public AnalysisSession(String method, String url, String fullRequest,
                           String requestBody, String responseBody, int statusCode) {
        this.id = generateId();
        this.timestamp = LocalDateTime.now().format(FMT);
        this.method = method;
        this.url = url;
        this.fullRequest = fullRequest != null && fullRequest.length() > 4000
                ? fullRequest.substring(0, 4000) + "\n[... truncated ...]"
                : fullRequest;
        this.requestBody = requestBody;
        this.statusCode = statusCode;
        // Keep first 3000 chars of response to give the model more to work with
        this.responseSnippet = responseBody != null && responseBody.length() > 3000
                ? responseBody.substring(0, 3000) + "\n[... truncated ...]"
                : responseBody;
        this.conversationHistory = new ArrayList<>();
        this.analysisLog = new ArrayList<>();
    }

    private String generateId() {
        return Long.toHexString(System.nanoTime()).substring(0, 8).toUpperCase();
    }

    /**
     * Builds the initial analysis prompt from the captured request/response.
     * Sends the FULL raw request (headers included) so the model can see
     * cookies, auth headers, content-type, custom headers, etc.
     */
    public String buildInitialPrompt() {
        StringBuilder sb = new StringBuilder();
        sb.append("Analyze this request and response. Full raw request including headers:\n\n");
        if (fullRequest != null && !fullRequest.isBlank()) {
            sb.append(fullRequest);
        } else {
            sb.append(method).append(" ").append(url).append("\n");
            if (requestBody != null && !requestBody.isBlank()) {
                sb.append("\n").append(requestBody);
            }
        }
        sb.append("\n\n--- RESPONSE (status ").append(statusCode).append(") ---\n\n");
        if (responseSnippet != null && !responseSnippet.isBlank()) {
            sb.append(responseSnippet);
        } else {
            sb.append("(empty or not captured)");
        }
        return sb.toString();
    }

    public void addUserMessage(String content) {
        conversationHistory.add(LlmClient.ChatMessage.user(content));
    }

    public void addAssistantMessage(String content) {
        conversationHistory.add(LlmClient.ChatMessage.assistant(content));
        analysisLog.add("[" + LocalDateTime.now().format(FMT) + "] " + content);
    }

    public List<LlmClient.ChatMessage> getConversationHistory() {
        return conversationHistory;
    }

    /**
     * Builds a bounded, content-filter-friendly view of the conversation to send
     * to the LLM. Resending the entire transcript on every turn (a) balloons the
     * token count and (b) on a moderated OpenAI-compatible gateway, repeatedly
     * re-exposes the model's OWN prior offensive analysis to the content filter —
     * which is what trips finish_reason=content_filter after the first turn.
     *
     * Strategy:
     *   - keep the initial request/response message (msg 0) as grounding,
     *   - once the session gets long, drop the oldest middle turns and keep only
     *     a recent window,
     *   - truncate prior ASSISTANT analyses (the bulky, most filter-triggering
     *     part) to maxAssistantChars, while leaving USER turns (the latest test
     *     results we actually want analyzed) intact.
     *
     * The conversation strictly alternates user/assistant and ends on a user
     * message at every call site, so keeping msg 0 plus an even-sized tail
     * preserves valid alternation for strict backends.
     */
    public List<LlmClient.ChatMessage> buildLlmHistory(int maxAssistantChars, int maxTailMessages) {
        List<LlmClient.ChatMessage> windowed;
        if (conversationHistory.size() <= maxTailMessages + 1) {
            windowed = new ArrayList<>(conversationHistory);
        } else {
            windowed = new ArrayList<>();
            windowed.add(conversationHistory.get(0)); // initial grounding (user)
            // An even tail begins on an assistant message, so prepending the
            // initial user message keeps the user/assistant alternation intact.
            int tail = (maxTailMessages % 2 == 0) ? maxTailMessages : maxTailMessages - 1;
            for (int i = conversationHistory.size() - tail; i < conversationHistory.size(); i++) {
                windowed.add(conversationHistory.get(i));
            }
        }

        List<LlmClient.ChatMessage> out = new ArrayList<>(windowed.size());
        for (LlmClient.ChatMessage m : windowed) {
            if ("assistant".equals(m.role) && m.content != null && m.content.length() > maxAssistantChars) {
                out.add(LlmClient.ChatMessage.assistant(
                        m.content.substring(0, maxAssistantChars)
                                + "\n[... prior analysis truncated to save tokens ...]"));
            } else {
                out.add(m);
            }
        }
        return out;
    }

    /**
     * Drops the accumulated follow-up turns, keeping only the initial
     * request/response and the first analysis. Used as an operator escape hatch
     * ("reset") to recover from a saturated context that the gateway keeps
     * content-filtering, without losing the original grounding.
     */
    public void resetToGrounding() {
        List<LlmClient.ChatMessage> keep = new ArrayList<>();
        if (!conversationHistory.isEmpty()) keep.add(conversationHistory.get(0));
        if (conversationHistory.size() > 1) keep.add(conversationHistory.get(1));
        conversationHistory.clear();
        conversationHistory.addAll(keep);
    }

    // --- Getters ---
    public String getId() { return id; }
    public String getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getRequestBody() { return requestBody; }
    public int getStatusCode() { return statusCode; }
    public List<String> getAnalysisLog() { return analysisLog; }

    /**
     * Returns a short label for the session list.
     */
    public String getLabel() {
        String path = url;
        try {
            java.net.URI uri = java.net.URI.create(url);
            path = uri.getPath();
            if (path == null || path.isEmpty()) path = "/";
        } catch (Exception ignored) {}
        return "[" + id + "] " + method + " " + path;
    }

    /**
     * Exports the full session as a markdown-formatted string for notes/reporting.
     */
    public String exportMarkdown() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Analysis Session ").append(id).append("\n");
        sb.append("**Timestamp:** ").append(timestamp).append("\n");
        sb.append("**Target:** ").append(method).append(" ").append(url).append("\n");
        sb.append("**Status:** ").append(statusCode).append("\n\n");

        sb.append("## Request Body\n```\n");
        sb.append(requestBody != null ? requestBody : "(empty)");
        sb.append("\n```\n\n");

        sb.append("## Conversation Log\n\n");
        for (LlmClient.ChatMessage msg : conversationHistory) {
            String role = msg.role.equals("user") ? "**You:**" : "**Claude:**";
            sb.append(role).append("\n").append(msg.content).append("\n\n---\n\n");
        }
        return sb.toString();
    }

    // URI.create used in getLabel()
}
