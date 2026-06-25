# HackPilot = AI-Powered Request Analysis for Burp Suite

A Burp Suite extension that gives you an AI co-pilot for web application penetration testing. Right-click any request, get immediate vulnerability analysis with specific payloads, then follow up with additional context (IDOR IDs, RBAC tokens, tenant data) for targeted access control testing.

**No PortSwigger AI credits required.** Uses your own API key with any OpenAI-compatible backend.

## Features

- **Right-click analysis** — Select any request in Proxy, Repeater, Logger, or Site Map → "Analyze with HackPilot"
- **Conversational follow-up** — Add context like tenant IDs, admin tokens, or role information and get specific IDOR/RBAC test cases
- **Persistent session log** — Every analysis accumulates in a dedicated tab, building your attack path narrative
- **Export to Markdown** — Export individual sessions or the full engagement log for your report
- **Multi-backend support** — Works with Anthropic (Claude), OpenAI, Ollama, vLLM, LM Studio, or any OpenAI-compatible API
- **Zero data to PortSwigger** — All LLM communication goes directly to your configured endpoint

## Supported LLM Backends

| Provider | API Base URL | API Key | Example Model |
|----------|-------------|---------|---------------|
| **Anthropic** | `https://api.anthropic.com` | Your Anthropic key | `claude-sonnet-4-20250514` |
| **OpenAI** | `https://api.openai.com` | Your OpenAI key | `gpt-4o` |
| **Ollama** | `http://localhost:11434/v1` | (leave blank) | `llama3.2` |
| **vLLM** | `http://localhost:8000` | (leave blank) | `meta-llama/Llama-3-8b` |
| **LM Studio** | `http://localhost:1234` | (leave blank) | (auto-detected) |

The extension auto-detects Anthropic's native API format vs OpenAI-compatible format based on the URL.

## Building

Requires Java 17+ and Gradle.

```bash
# Clone and build
cd burp-claude-extension
./gradlew shadowJar

# The JAR will be at:
# build/libs/HackPilot-1.0.0.jar
```

## Installation

1. Open Burp Suite → Extensions → Installed
2. Click "Add"
3. Extension type: Java
4. Select `build/libs/HackPilot-1.0.0.jar`
5. Go to the "HackPilot" tab and configure your API key

## Usage

### Basic Analysis
1. Browse to a target through Burp's proxy
2. Find an interesting request (POST with body parameters, API endpoints with IDs, etc.)
3. Right-click → "Analyze with HackPilot"
4. Switch to the HackPilot tab to see the analysis

### Follow-up with Context
After the initial analysis, use the prompt field at the bottom to provide additional context:

```
Here are user IDs from tenant B: 4502, 4503, 4510. Test for IDOR on the userId parameter.
```

```
I have an admin session token: Bearer eyJhbG... — what privilege escalation tests should I run against this endpoint?
```

```
The application uses sequential integer IDs for orders. Current user's orders are 1001-1005. 
Test for horizontal access control bypass.
```

### Export for Reporting
- **Export Session** — Save a single analysis session as Markdown
- **Export All** — Save all sessions as a combined engagement log

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Burp Suite                                             │
│  ┌─────────────┐  ┌──────────────────────────────────┐  │
│  │ Context Menu │→ │ HackPilot Tab                 │  │
│  │ (right-click)│  │ ┌────────┐ ┌──────────────────┐ │  │
│  └─────────────┘  │ │Sessions│ │ Analysis Output  │ │  │
│                    │ │  List  │ │ + Conversation   │ │  │
│                    │ │        │ │                  │ │  │
│                    │ └────────┘ └──────────────────┘ │  │
│                    │            ┌──────────────────┐ │  │
│                    │            │ Follow-up Prompt │ │  │
│                    │            └──────────────────┘ │  │
│                    └──────────────────────────────────┘  │
│                              │                          │
│                              ▼                          │
│                    ┌──────────────────┐                  │
│                    │   LLM Client     │                  │
│                    │ (Anthropic/OAI)  │                  │
│                    └──────────────────┘                  │
│                              │                          │
└──────────────────────────────│──────────────────────────┘
                               ▼
                    ┌──────────────────┐
                    │  Your LLM API    │
                    │  (Claude, etc.)  │
                    └──────────────────┘
```

## Project Structure

```
src/main/java/com/hackpilot/
├── HackPilotExtension.java  — Entry point, context menu, Montoya API wiring
├── PilotPanel.java             — Main UI tab (sessions, output, prompt input, settings)
├── AnalysisSession.java        — Per-request conversation state and export
├── LlmClient.java              — HTTP client for Anthropic + OpenAI-compatible APIs
└── Prompts.java                — System prompts (the AI's pentesting instructions)
```

## Customizing the System Prompt

Edit `Prompts.java` to adjust the AI's behavior. The default prompt is tuned for a senior pentester who wants specific, actionable findings — not generic OWASP summaries.

## Security Notes

- Your API key is stored in memory only (not persisted to disk)
- All LLM traffic bypasses Burp's proxy — it goes directly to your API endpoint
- Request/response data is sent to whichever LLM backend you configure
- For maximum data control, use a local model via Ollama

## License

MIT — Use it, modify it, break things with it (legally).
