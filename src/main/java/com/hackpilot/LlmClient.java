package com.hackpilot;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * LLM API client that supports any OpenAI-compatible endpoint.
 * Works with: Anthropic (via OpenAI compat), OpenAI, Ollama, vLLM, LM Studio, etc.
 *
 * For Anthropic's native API: set apiBase to "https://api.anthropic.com" and
 * the client will auto-detect and use the /v1/messages endpoint format.
 */
public class LlmClient {

    public enum ApiFormat {
        OPENAI_COMPATIBLE,  // /v1/chat/completions (OpenAI, Ollama, vLLM, LM Studio)
        ANTHROPIC_NATIVE    // /v1/messages (Anthropic's own API)
    }

    private String apiBase;
    private String apiKey;
    private String model;
    private ApiFormat format;
    private boolean tlsVerify = true;
    private final Gson gson = new Gson();
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "HackPilot-LLM");
        t.setDaemon(true);
        return t;
    });

    public LlmClient(String apiBase, String apiKey, String model) {
        this.apiBase = apiBase.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.model = model;

        // Auto-detect Anthropic native API
        if (this.apiBase.contains("anthropic.com")) {
            this.format = ApiFormat.ANTHROPIC_NATIVE;
        } else {
            this.format = ApiFormat.OPENAI_COMPATIBLE;
        }
    }

    public void setApiBase(String apiBase) {
        this.apiBase = apiBase.replaceAll("/+$", "");
        if (this.apiBase.contains("anthropic.com")) {
            this.format = ApiFormat.ANTHROPIC_NATIVE;
        } else {
            this.format = ApiFormat.OPENAI_COMPATIBLE;
        }
    }

    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    public void setModel(String model) { this.model = model; }
    public void setTlsVerify(boolean verify) { this.tlsVerify = verify; }
    public boolean getTlsVerify() { return tlsVerify; }
    public String getApiBase() { return apiBase; }
    public String getApiKey() { return apiKey; }
    public String getModel() { return model; }
    public ApiFormat getFormat() { return format; }

    /**
     * Sends a chat completion request synchronously.
     */
    public String chat(String systemPrompt, List<ChatMessage> messages) throws Exception {
        if (format == ApiFormat.ANTHROPIC_NATIVE) {
            return chatAnthropic(systemPrompt, messages);
        } else {
            return chatOpenAI(systemPrompt, messages);
        }
    }

    /**
     * Sends a chat completion request asynchronously.
     */
    public CompletableFuture<String> chatAsync(String systemPrompt, List<ChatMessage> messages) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return chat(systemPrompt, messages);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, executor);
    }

    private String chatOpenAI(String systemPrompt, List<ChatMessage> messages) throws Exception {
        String url = apiBase + "/v1/chat/completions";

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("max_tokens", 4096);
        body.addProperty("temperature", 0.3);

        JsonArray msgArray = new JsonArray();

        // System message
        JsonObject sysMsg = new JsonObject();
        sysMsg.addProperty("role", "system");
        sysMsg.addProperty("content", systemPrompt);
        msgArray.add(sysMsg);

        // Conversation messages
        for (ChatMessage msg : messages) {
            JsonObject m = new JsonObject();
            m.addProperty("role", msg.role);
            m.addProperty("content", msg.content);
            msgArray.add(m);
        }

        body.add("messages", msgArray);

        String response = doPost(url, body.toString(), false);

        JsonObject parsed;
        try {
            parsed = JsonParser.parseString(response).getAsJsonObject();
        } catch (Exception e) {
            throw new LlmException(LlmException.Kind.MALFORMED,
                    "Could not parse LLM response as JSON. Raw: " + snippet(response));
        }

        JsonArray choices = parsed.getAsJsonArray("choices");
        if (choices == null || choices.size() == 0) {
            throw new LlmException(LlmException.Kind.MALFORMED,
                    "LLM response contained no choices. Raw: " + snippet(response));
        }

        JsonObject choice = choices.get(0).getAsJsonObject();
        String finishReason = optString(choice, "finish_reason");

        String content = "";
        if (choice.has("message") && choice.get("message").isJsonObject()) {
            content = optString(choice.getAsJsonObject("message"), "content");
        }

        // A moderating OpenAI-compatible gateway (e.g. a LiteLLM guardrail) signals a
        // block with finish_reason=content_filter and an empty body. Surface it loudly
        // instead of returning "" — otherwise the caller silently shows no analysis.
        if ("content_filter".equalsIgnoreCase(finishReason)) {
            throw new LlmException(LlmException.Kind.CONTENT_FILTER,
                    "The LLM gateway blocked this turn (finish_reason=content_filter). "
                  + "This is a moderation/guardrail decision on the backend, not a Burp error. "
                  + tokenInfo(parsed));
        }
        if (content.isBlank()) {
            throw new LlmException(LlmException.Kind.EMPTY,
                    "LLM returned no text (finish_reason="
                  + (finishReason.isEmpty() ? "unknown" : finishReason) + "). " + tokenInfo(parsed));
        }
        return content;
    }

    private String chatAnthropic(String systemPrompt, List<ChatMessage> messages) throws Exception {
        String url = apiBase + "/v1/messages";

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("max_tokens", 4096);
        body.addProperty("system", systemPrompt);

        JsonArray msgArray = new JsonArray();
        for (ChatMessage msg : messages) {
            JsonObject m = new JsonObject();
            m.addProperty("role", msg.role);
            m.addProperty("content", msg.content);
            msgArray.add(m);
        }
        body.add("messages", msgArray);

        String response = doPost(url, body.toString(), true);

        JsonObject parsed;
        try {
            parsed = JsonParser.parseString(response).getAsJsonObject();
        } catch (Exception e) {
            throw new LlmException(LlmException.Kind.MALFORMED,
                    "Could not parse Anthropic response as JSON. Raw: " + snippet(response));
        }

        String stopReason = optString(parsed, "stop_reason");
        JsonArray content = parsed.getAsJsonArray("content");
        StringBuilder sb = new StringBuilder();
        if (content != null) {
            for (int i = 0; i < content.size(); i++) {
                JsonObject block = content.get(i).getAsJsonObject();
                if ("text".equals(optString(block, "type"))) {
                    sb.append(optString(block, "text"));
                }
            }
        }
        if (sb.length() == 0) {
            throw new LlmException(LlmException.Kind.EMPTY,
                    "Anthropic API returned no text (stop_reason="
                  + (stopReason.isEmpty() ? "unknown" : stopReason) + ").");
        }
        return sb.toString();
    }

    private String doPost(String urlStr, String jsonBody, boolean isAnthropic) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) URI.create(urlStr).toURL().openConnection();

        // Disable TLS verification if toggled off (for internal/self-signed certs)
        if (!tlsVerify && conn instanceof HttpsURLConnection) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            httpsConn.setSSLSocketFactory(sc.getSocketFactory());
            httpsConn.setHostnameVerifier((hostname, session) -> true);
        }

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(120000);
        conn.setDoOutput(true);

        if (isAnthropic) {
            conn.setRequestProperty("x-api-key", apiKey);
            conn.setRequestProperty("anthropic-version", "2023-06-01");
        } else {
            if (apiKey != null && !apiKey.isBlank()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            }
        }

        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }

        int status = conn.getResponseCode();
        BufferedReader reader;
        if (status >= 200 && status < 300) {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
        }

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        conn.disconnect();

        if (status < 200 || status >= 300) {
            throw new Exception("LLM API error (HTTP " + status + "): " + response);
        }

        return response.toString();
    }

    // ─── response helpers ───────────────────────────────────────────────

    /** Null-safe string read: returns "" for a missing/null key instead of throwing. */
    private static String optString(JsonObject obj, String key) {
        if (obj == null || !obj.has(key) || obj.get(key).isJsonNull()) return "";
        try {
            return obj.get(key).getAsString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String snippet(String s) {
        if (s == null) return "(null)";
        return s.length() > 500 ? s.substring(0, 500) + " ..." : s;
    }

    private static String tokenInfo(JsonObject parsed) {
        try {
            JsonObject usage = parsed.getAsJsonObject("usage");
            if (usage != null) {
                return "[prompt_tokens=" + optString(usage, "prompt_tokens")
                     + ", completion_tokens=" + optString(usage, "completion_tokens") + "]";
            }
        } catch (Exception ignored) {}
        return "";
    }

    public void shutdown() {
        executor.shutdown();
    }

    /**
     * Raised when the backend returns something other than usable text — a
     * content-filter/guardrail block, an empty body, an incomplete generation,
     * or a malformed response. Carries a {@link Kind} so the UI can react
     * appropriately (e.g. offer to trim context on a content-filter block)
     * instead of treating an empty string as a valid (blank) analysis.
     */
    public static class LlmException extends Exception {
        public enum Kind { CONTENT_FILTER, INCOMPLETE, EMPTY, MALFORMED }

        public final Kind kind;

        public LlmException(Kind kind, String message) {
            super(message);
            this.kind = kind;
        }
    }

    /**
     * Simple chat message DTO.
     */
    public static class ChatMessage {
        public final String role;
        public final String content;

        public ChatMessage(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public static ChatMessage user(String content) {
            return new ChatMessage("user", content);
        }

        public static ChatMessage assistant(String content) {
            return new ChatMessage("assistant", content);
        }
    }
}
