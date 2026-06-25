package com.hackpilot;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sends modified HTTP requests through Burp's HTTP stack.
 *
 * Takes the ORIGINAL captured request (byte-perfect from the browser)
 * and applies parameter/header/path modifications specified by the LLM.
 * This ensures all formatting, encoding, cookies, and headers remain valid.
 *
 * Body editing is content-type aware:
 *   - JSON (application/json, application/vnd.api+json, application/ld+json,
 *     application/*+json, text/json, or a body that simply starts with { or [):
 *     parsed with Gson and edited via a DOTTED PATH (object keys + numeric
 *     array indices), so nested structures and JSON:API bodies are handled
 *     correctly instead of being corrupted by a stray "&name=value" append.
 *   - multipart/form-data: the named part's value is replaced in place.
 *   - everything else: treated as a URL-encoded body / query string, with the
 *     parameter name anchored to a boundary so "id" does not match "userid".
 *
 * All traffic is visible in Burp Logger (Sources -> Extensions).
 */
public class BurpHttpSender {

    private final MontoyaApi api;

    // disableHtmlEscaping keeps payloads like <script> or ' intact instead of
    // re-encoding them as \u003c / \u0027 when we serialize a modified JSON body.
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    public BurpHttpSender(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Applies a TestProposal modification to the original request and sends it.
     *
     * @param originalRequest The original HttpRequest captured from Burp (byte-perfect)
     * @param proposal        The test proposal with modification instructions
     * @return SendResult with status, headers, and body
     */
    public SendResult sendModifiedRequest(HttpRequest originalRequest, TestProposal proposal) {
        try {
            HttpRequest modified = applyModification(originalRequest, proposal);

            // Send through Burp's HTTP stack — visible in Logger
            HttpRequestResponse result = api.http().sendRequest(modified);

            HttpResponse response = result.response();
            if (response == null) {
                return new SendResult(0, "", "(no response received)");
            }

            StringBuilder headers = new StringBuilder();
            response.headers().forEach(h ->
                    headers.append(h.name()).append(": ").append(h.value()).append("\n")
            );

            return new SendResult(
                    response.statusCode(),
                    headers.toString(),
                    response.bodyToString()
            );
        } catch (Exception e) {
            // Surface modification/parse failures here so they show up in the panel
            // (and trip the circuit breaker) instead of silently sending a bad request.
            return new SendResult(0, "", "ERROR: " + e.getMessage());
        }
    }

    /**
     * Applies the modification from a TestProposal to the original request.
     */
    private HttpRequest applyModification(HttpRequest original, TestProposal proposal) {
        switch (proposal.getModType()) {
            case PARAM:
                return modifyParameter(original, proposal.getTarget(), proposal.getValue());
            case HEADER:
                return modifyHeader(original, proposal.getTarget(), proposal.getValue());
            case PATH:
                return modifyPath(original, proposal.getValue());
            default:
                return original;
        }
    }

    // ─── Parameter routing ──────────────────────────────────────────────

    /**
     * Modifies a parameter in the request body or query string.
     * Routes to a JSON / multipart / URL-encoded handler based on Content-Type,
     * with a body sniff as a backstop when the header is missing or unusual.
     */
    private HttpRequest modifyParameter(HttpRequest original, String paramName, String newValue) {
        String body = original.bodyToString();
        String contentType = getHeaderValue(original, "Content-Type");
        String ct = (contentType == null) ? "" : contentType.toLowerCase();

        // "json" matches application/json, application/vnd.api+json (JSON:API),
        // application/ld+json, application/*+json, text/json, etc. The previous
        // code checked contains("application/json"), which is FALSE for
        // "application/vnd.api+json" (not a contiguous substring) and caused the
        // request to fall through to the URL-encoded path and get "&id=..." appended.
        boolean looksJson = ct.contains("json") || isJsonBody(body);

        if (looksJson) {
            return modifyJsonParam(original, body, paramName, newValue);
        } else if (ct.contains("multipart/form-data")) {
            return modifyMultipartParam(original, body, paramName, newValue, contentType);
        } else {
            return modifyUrlEncodedParam(original, body, paramName, newValue);
        }
    }

    /** Heuristic backstop: a body that starts with { or [ is JSON even if the header lies. */
    private static boolean isJsonBody(String body) {
        if (body == null) return false;
        String t = body.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    // ─── JSON body (dotted-path, type-aware) ────────────────────────────

    /**
     * Edits a JSON body by parsing it and walking a dotted path to the target.
     *
     * The target is a PATH, not a flat name:
     *   data.attributes.email
     *   data.id
     *   data.relationships.agents.data.0.id   (0 indexes the first array element)
     *
     * If the final key does not exist on an object it is ADDED (mass-assignment
     * testing). Out-of-range indices and bad paths throw — surfaced as an ERROR
     * SendResult rather than a silently mangled request.
     */
    private HttpRequest modifyJsonParam(HttpRequest original, String body,
                                        String paramPath, String newValue) {
        if (body == null || body.isBlank()) {
            throw new IllegalArgumentException(
                    "HackPilot: empty body, cannot apply JSON MODIFY_PARAM '" + paramPath + "'");
        }

        JsonElement root;
        try {
            root = JsonParser.parseString(body);
        } catch (JsonSyntaxException e) {
            throw new IllegalArgumentException(
                    "HackPilot: body is not valid JSON, cannot apply MODIFY_PARAM '" + paramPath + "'");
        }

        setByPath(root, paramPath.trim(), newValue);
        return original.withBody(gson.toJson(root));
    }

    /** Navigates a dotted path (object keys + numeric array indices) and sets the final value. */
    private void setByPath(JsonElement root, String path, String newValue) {
        String[] segs = path.split("\\.");
        JsonElement current = root;

        for (int i = 0; i < segs.length - 1; i++) {
            String seg = segs[i].trim();
            current = unwrapSingletonArray(current, seg);
            current = descend(current, seg, path);
        }

        String last = segs[segs.length - 1].trim();
        current = unwrapSingletonArray(current, last);
        JsonElement value = toJsonValue(newValue);

        if (current.isJsonArray()) {
            JsonArray arr = current.getAsJsonArray();
            int idx = parseIndex(last, path);
            if (idx < 0 || idx >= arr.size()) {
                throw new IllegalArgumentException(
                        "HackPilot: array index " + idx + " out of bounds for path '" + path + "'");
            }
            arr.set(idx, value);
        } else if (current.isJsonObject()) {
            // add() replaces an existing key or inserts a new one (mass assignment).
            current.getAsJsonObject().add(last, value);
        } else {
            throw new IllegalArgumentException(
                    "HackPilot: cannot set '" + last + "' on a JSON primitive at path '" + path + "'");
        }
    }

    /** Steps one level into an object key or array index. */
    private JsonElement descend(JsonElement current, String seg, String fullPath) {
        if (current.isJsonArray()) {
            JsonArray arr = current.getAsJsonArray();
            int idx = parseIndex(seg, fullPath);
            if (idx < 0 || idx >= arr.size()) {
                throw new IllegalArgumentException(
                        "HackPilot: array index " + idx + " out of bounds for path '" + fullPath + "'");
            }
            return arr.get(idx);
        } else if (current.isJsonObject()) {
            JsonObject obj = current.getAsJsonObject();
            if (!obj.has(seg)) {
                throw new IllegalArgumentException(
                        "HackPilot: path segment '" + seg + "' not found in '" + fullPath + "'");
            }
            return obj.get(seg);
        }
        throw new IllegalArgumentException(
                "HackPilot: cannot descend into '" + seg + "' for path '" + fullPath + "'");
    }

    private int parseIndex(String seg, String fullPath) {
        try {
            return Integer.parseInt(seg.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "HackPilot: expected an array index but got '" + seg + "' in path '" + fullPath + "'");
        }
    }

    /**
     * Transparently steps into element 0 of a SINGLE-element array when the next
     * path segment is a name rather than an index. This makes common array-wrapped
     * bodies like [{"data":{...}}] addressable as data.attributes.name without the
     * caller having to write the leading "0." index.
     *
     * It only fires when there is exactly one element (no ambiguity). A multi-element
     * array is left untouched, so a name segment against it still errors loudly via
     * parseIndex — the model must say WHICH element it means. Repeats for nested
     * wrappers such as [[{...}]].
     */
    private JsonElement unwrapSingletonArray(JsonElement current, String nextSeg) {
        while (current.isJsonArray() && !isIndex(nextSeg)) {
            JsonArray arr = current.getAsJsonArray();
            if (arr.size() != 1) break;   // ambiguous — leave it for the caller to reject
            current = arr.get(0);
        }
        return current;
    }

    private boolean isIndex(String seg) {
        if (seg == null) return false;
        try {
            Integer.parseInt(seg.trim());
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Converts a MODIFY_PARAM value into a JSON element.
     *
     * Default is a STRING so payloads are preserved verbatim — leading zeros,
     * SQLi tautologies, XSS, etc. survive intact. Type prefixes give explicit
     * control when you need a non-string:
     *
     *   num:123        -> JSON number
     *   bool:true      -> JSON boolean
     *   null           -> JSON null
     *   json:{"a":1}   -> raw JSON value (inject an object/array, e.g. type juggling)
     *   str:0001       -> force a string even if the value looks numeric
     */
    private JsonElement toJsonValue(String raw) {
        String t = (raw == null) ? "" : raw.trim();
        if (t.equals("null"))      return JsonNull.INSTANCE;
        if (t.startsWith("num:"))  return new JsonPrimitive(new java.math.BigDecimal(t.substring(4).trim()));
        if (t.startsWith("bool:")) return new JsonPrimitive(Boolean.parseBoolean(t.substring(5).trim()));
        if (t.startsWith("json:")) return JsonParser.parseString(t.substring(5).trim());
        if (t.startsWith("str:"))  return new JsonPrimitive(t.substring(4));
        return new JsonPrimitive(raw == null ? "" : raw);
    }

    // ─── multipart/form-data ────────────────────────────────────────────

    private HttpRequest modifyMultipartParam(HttpRequest original, String body,
                                              String paramName, String newValue, String contentType) {
        // Find the boundary
        String boundary = "";
        for (String part : contentType.split(";")) {
            part = part.trim();
            if (part.startsWith("boundary=")) {
                boundary = part.substring(9).trim();
                break;
            }
        }

        if (boundary.isEmpty() || body == null) {
            return original;
        }

        // Find the part with this parameter name and replace its value
        // Pattern: Content-Disposition: form-data; name="paramName"\r\n\r\n<value>\r\n
        String partHeader = "name=\"" + paramName + "\"";
        int headerIdx = body.indexOf(partHeader);
        if (headerIdx < 0) {
            return original;
        }

        // Find the blank line after headers (value starts after \r\n\r\n or \n\n)
        int valueStart = body.indexOf("\r\n\r\n", headerIdx);
        int lineEndLen = 4;
        if (valueStart < 0) {
            valueStart = body.indexOf("\n\n", headerIdx);
            lineEndLen = 2;
        }
        if (valueStart < 0) return original;
        valueStart += lineEndLen;

        // Find the boundary that ends this part
        int valueEnd = body.indexOf(boundary, valueStart);
        if (valueEnd < 0) return original;

        // Back up past the \r\n-- before the boundary
        int actualEnd = valueEnd;
        while (actualEnd > valueStart && (body.charAt(actualEnd - 1) == '-' ||
               body.charAt(actualEnd - 1) == '\r' || body.charAt(actualEnd - 1) == '\n')) {
            actualEnd--;
        }

        String modifiedBody = body.substring(0, valueStart) + newValue + body.substring(actualEnd);
        return original.withBody(modifiedBody);
    }

    // ─── URL-encoded body / query string ────────────────────────────────

    private HttpRequest modifyUrlEncodedParam(HttpRequest original, String body,
                                              String paramName, String newValue) {
        // 1) URL-encoded body parameter (boundary-anchored, so "id" != "userid").
        if (body != null) {
            String modifiedBody = replaceUrlParam(body, paramName, newValue);
            if (!modifiedBody.equals(body)) {
                return original.withBody(modifiedBody);
            }
        }

        // 2) Query-string parameter. Operate on the request target (path + query)
        //    via original.path(), NOT the absolute URL. The previous code did
        //    url.substring(url.indexOf('/')), which on "https://host/p?x=1" returns
        //    "//host/p?x=1" — a corrupted request line.
        String pathWithQuery = original.path();
        if (pathWithQuery != null) {
            String modifiedPath = replaceUrlParam(pathWithQuery, paramName, newValue);
            if (!modifiedPath.equals(pathWithQuery)) {
                return original.withPath(modifiedPath);
            }
        }

        // 3) Not present anywhere — append as a new parameter
        //    (hidden-parameter / mass-assignment probe).
        String separator = (body != null && !body.isEmpty()) ? "&" : "";
        String newBody = (body != null ? body : "") + separator + paramName + "=" + newValue;
        return original.withBody(newBody);
    }

    /**
     * Replaces paramName=&lt;value&gt; with paramName=newValue, anchored to a boundary
     * (start-of-string, '?' or '&') so a short name like "id" does not also match
     * "userid". Returns the input unchanged if the parameter is not present.
     */
    private String replaceUrlParam(String data, String paramName, String newValue) {
        Pattern p = Pattern.compile("(^|[?&])" + Pattern.quote(paramName) + "=[^&]*");
        Matcher m = p.matcher(data);
        // $1 preserves the matched boundary char; quoteReplacement escapes $ and \
        // in the literal value so payloads containing them are not mangled or thrown.
        String replacement = "$1" + Matcher.quoteReplacement(paramName + "=" + newValue);
        return m.replaceAll(replacement);
    }

    // ─── header / path ──────────────────────────────────────────────────

    private HttpRequest modifyHeader(HttpRequest original, String headerName, String newValue) {
        return original.withRemovedHeader(headerName).withAddedHeader(headerName, newValue);
    }

    private HttpRequest modifyPath(HttpRequest original, String newPath) {
        return original.withPath(newPath);
    }

    private String getHeaderValue(HttpRequest request, String name) {
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst()
                .orElse(null);
    }

    /**
     * Result of sending a request.
     */
    public static class SendResult {
        public final int statusCode;
        public final String headers;
        public final String body;

        public SendResult(int statusCode, String headers, String body) {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }
    }
}
