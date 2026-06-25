package com.hackpilot;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a single test proposal extracted from the LLM's response.
 *
 * The LLM outputs structured PROPOSE_TEST blocks that specify which
 * parameter to modify and what value to use. The extension then applies
 * the modification to the original captured request — keeping all headers,
 * cookies, encoding, and formatting intact.
 *
 * Supports three modification types:
 *   PARAM:   body/query parameter substitution
 *   HEADER:  header value substitution
 *   PATH:    URL path modification
 */
public class TestProposal {

    public enum Status { PENDING, APPROVED, SKIPPED, SENT, ANALYZED }

    public enum ModType { PARAM, HEADER, PATH }

    private final int index;
    private final String name;
    private final String reasoning;
    private final ModType modType;
    private final String target;    // parameter name, header name, or "path"
    private final String value;     // new value to set
    private Status status;
    private String responseBody;
    private int responseStatus;
    private String responseHeaders;

    public TestProposal(int index, String name, String reasoning,
                        ModType modType, String target, String value) {
        this.index = index;
        this.name = name;
        this.reasoning = reasoning;
        this.modType = modType;
        this.target = target;
        this.value = value;
        this.status = Status.PENDING;
    }

    // --- Getters/Setters ---
    public int getIndex() { return index; }
    public String getName() { return name; }
    public String getReasoning() { return reasoning; }
    public ModType getModType() { return modType; }
    public String getTarget() { return target; }
    public String getValue() { return value; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public int getResponseStatus() { return responseStatus; }
    public String getResponseHeaders() { return responseHeaders; }
    public String getResponseBody() { return responseBody; }

    public void setResponse(int status, String headers, String body) {
        this.responseStatus = status;
        this.responseHeaders = headers;
        this.responseBody = body;
    }

    /**
     * Parses PROPOSE_TEST blocks from the LLM response.
     *
     * Expected format:
     *
     * PROPOSE_TEST: SQL injection on email_address
     * REASONING: Testing auth bypass via tautology injection
     * MODIFY_PARAM: email_address = admin' OR '1'='1
     * END_TEST
     *
     * Or for headers:
     *
     * PROPOSE_TEST: Test with admin auth token
     * REASONING: Check if endpoint returns different data with elevated privileges
     * MODIFY_HEADER: Authorization = Bearer eyJhbGci...
     * END_TEST
     *
     * Or for path:
     *
     * PROPOSE_TEST: Check for admin panel
     * REASONING: Common admin path enumeration
     * MODIFY_PATH: /admin/dashboard
     * END_TEST
     */
    public static List<TestProposal> parseFromResponse(String response) {
        List<TestProposal> proposals = new ArrayList<>();

        Pattern pattern = Pattern.compile(
                "PROPOSE_TEST:\\s*(.+?)\\s*\\n" +
                "REASONING:\\s*(.+?)\\s*\\n" +
                "MODIFY_(PARAM|HEADER|PATH):\\s*(.+?)\\s*\\n" +
                "END_TEST",
                Pattern.DOTALL
        );

        Matcher matcher = pattern.matcher(response);
        int idx = 0;
        while (matcher.find()) {
            String name = matcher.group(1).trim();
            String reasoning = matcher.group(2).trim();
            String typeStr = matcher.group(3).trim().toUpperCase();
            String modLine = matcher.group(4).trim();

            ModType modType;
            String target;
            String value;

            switch (typeStr) {
                case "PARAM":
                    modType = ModType.PARAM;
                    // Parse "param_name = value"
                    int eqIdx = modLine.indexOf('=');
                    if (eqIdx > 0) {
                        target = modLine.substring(0, eqIdx).trim();
                        value = modLine.substring(eqIdx + 1).trim();
                    } else {
                        target = modLine;
                        value = "";
                    }
                    break;
                case "HEADER":
                    modType = ModType.HEADER;
                    int colonIdx = modLine.indexOf('=');
                    if (colonIdx > 0) {
                        target = modLine.substring(0, colonIdx).trim();
                        value = modLine.substring(colonIdx + 1).trim();
                    } else {
                        target = modLine;
                        value = "";
                    }
                    break;
                case "PATH":
                    modType = ModType.PATH;
                    target = "path";
                    value = modLine;
                    break;
                default:
                    continue;
            }

            proposals.add(new TestProposal(idx++, name, reasoning, modType, target, value));
        }

        return proposals;
    }

    /**
     * Display string for the output pane.
     */
    public String toDisplayString() {
        StringBuilder sb = new StringBuilder();
        sb.append("  NAME: ").append(name).append("\n");
        sb.append("  WHY:  ").append(reasoning).append("\n");
        sb.append("  CHANGE: ").append(modType).append(" ").append(target);
        sb.append(" = ").append(value).append("\n");
        sb.append("  STATUS: ").append(status).append("\n");
        return sb.toString();
    }

    /**
     * Builds a result summary to feed back to the LLM for auto-analysis.
     */
    public String buildResultFeedback() {
        StringBuilder sb = new StringBuilder();
        sb.append("Test: ").append(name).append("\n");
        // Redact the modification value: a full JWT (or similar token) doesn't help
        // the model reason about the RESULT, and re-sending the same large attack
        // blob on every analysis turn is exactly what re-triggers a gateway content
        // filter. The test name/reasoning already convey what was changed.
        sb.append("Modification: ").append(modType).append(" ").append(target);
        sb.append(" = ").append(redactSecrets(value)).append("\n");
        sb.append("Response status: ").append(responseStatus).append("\n");
        if (responseHeaders != null && !responseHeaders.isBlank()) {
            // Only include interesting headers, not all of them
            sb.append("Key response headers:\n");
            for (String line : responseHeaders.split("\\n")) {
                String lower = line.toLowerCase();
                if (lower.startsWith("set-cookie") || lower.startsWith("location") ||
                    lower.startsWith("x-") || lower.startsWith("content-type") ||
                    lower.startsWith("www-authenticate") || lower.startsWith("access-control")) {
                    sb.append("  ").append(redactSecrets(line)).append("\n");
                }
            }
        }
        if (responseBody != null) {
            String truncated = responseBody.length() > 1200
                    ? responseBody.substring(0, 1200) + "\n[... truncated ...]"
                    : responseBody;
            sb.append("Response body:\n").append(redactSecrets(truncated)).append("\n");
        }
        return sb.toString();
    }

    // Matches JWT-shaped blobs (header.payload[.signature]). These appear in
    // cookies/auth headers and are huge; collapsing them keeps the same token from
    // being re-scanned by the gateway's content filter on every analysis turn.
    private static final Pattern JWT_RE = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}(?:\\.[A-Za-z0-9_-]*)?");

    /** Replaces JWT-looking tokens with a short marker. */
    private static String redactSecrets(String s) {
        if (s == null) return null;
        return JWT_RE.matcher(s).replaceAll("[JWT redacted]");
    }
}
