"""
LeafScan — Unified AI Client Router
Supports 15+ AI providers including OpenRouter, OpenAI, Anthropic, Gemini, Ollama,
Groq, Mistral, Together, Cohere, DeepSeek, Perplexity, OpenClaw, Hermes, NewClaw, CoWork, and OpenCode.
"""
import json
import logging
import requests

logger = logging.getLogger("leafscan.ai")

AI_PROVIDERS = {
    "openrouter":  {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "openai/gpt-4o-mini"},
    "openai":      {"url": "https://api.openai.com/v1/chat/completions", "default_model": "gpt-4o-mini"},
    "anthropic":   {"url": "https://api.anthropic.com/v1/messages", "default_model": "claude-3-haiku-20240307"},
    "ollama":      {"url": "http://localhost:11434/v1/chat/completions", "default_model": "llama3.2"},
    "google":      {"url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "default_model": "gemini-1.5-flash"},
    "groq":        {"url": "https://api.groq.com/openai/v1/chat/completions", "default_model": "llama3-8b-8192"},
    "mistral":     {"url": "https://api.mistral.ai/v1/chat/completions", "default_model": "mistral-tiny"},
    "together":    {"url": "https://api.together.xyz/v1/chat/completions", "default_model": "mistralai/Mixtral-8x7B-Instruct-v0.1"},
    "cohere":      {"url": "https://api.cohere.com/v1/chat", "default_model": "command-r-plus"},
    "deepseek":    {"url": "https://api.deepseek.com/chat/completions", "default_model": "deepseek-chat"},
    "perplexity":  {"url": "https://api.perplexity.ai/chat/completions", "default_model": "llama-3-sonar-small-32k-chat"},
    "openclaw":    {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "nousresearch/hermes-3-llama-3.1-405b"},
    "hermes":      {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "nousresearch/hermes-3-llama-3.1-405b"},
    "newclaw":     {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "nousresearch/hermes-3-llama-3.1-405b"},
    "cowork":      {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "meta-llama/llama-3.1-70b-instruct"},
    "opencode":    {"url": "https://openrouter.ai/api/v1/chat/completions", "default_model": "meta-llama/codellama-70b-instruct"},
    "leaf-ai":     {"url": "local", "default_model": "leafgpt"},
}


class AIClient:
    def __init__(self, config):
        self.ai_cfg = config.get("ai", {})
        self.enabled = self.ai_cfg.get("enabled", False)
        self.provider = self.ai_cfg.get("provider", "openrouter").lower()
        self.api_key = self.ai_cfg.get("api_key", "")
        self.model = self.ai_cfg.get("model", "")
        self.api_url = self.ai_cfg.get("api_url", "")

        # Default provider fallback config
        prov_info = AI_PROVIDERS.get(self.provider, AI_PROVIDERS["openrouter"])
        if not self.model:
            self.model = prov_info["default_model"]
        if not self.api_url:
            self.api_url = prov_info["url"]

    def call_ai(self, prompt: str, system: str = "") -> str:
        if not self.enabled:
            return "⚠️ AI integration is not configured or enabled."
        if self.provider != "leaf-ai" and not self.api_key:
            return "⚠️ AI integration is configured but API key is missing. Run 'leafscan setup' to add."

        try:
            # 1. Handle custom Leaf Security AI local/RAG provider
            if self.provider == "leaf-ai":
                return self._call_leaf_ai(prompt, system)

            # 2. Handle Anthropic format separately
            if self.provider == "anthropic":
                return self._call_anthropic(prompt, system)

            # 3. Handle Cohere format separately
            if self.provider == "cohere" and "chat/completions" not in self.api_url:
                return self._call_cohere(prompt, system)

            # 4. Standard OpenAI-compatible format
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            # OpenRouter requires extra referrer headers
            if "openrouter.ai" in self.api_url:
                headers["HTTP-Referer"] = "https://github.com/Jovinap/leafscan"
                headers["X-Title"] = "LeafScan v2"

            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            body = {
                "model": self.model,
                "messages": messages,
                "temperature": 0.2
            }

            r = requests.post(self.api_url, headers=headers, json=body, timeout=20)
            if r.ok:
                resp_json = r.json()
                return resp_json["choices"][0]["message"]["content"]
            else:
                return f"AI API Error: {r.status_code} - {r.text}"

        except Exception as e:
            return f"Error contacting AI provider ({self.provider}): {e}"

    def _call_leaf_ai(self, prompt: str, system: str) -> str:
        import os
        import sys
        
        # 1. RAG Context Extraction from local 500MB dataset
        dataset_path = "/home/kali/.gemini/antigravity/scratch/leaf-ai-llm/leaf_security_ai_dataset.txt"
        context_snippets = []
        if os.path.exists(dataset_path):
            try:
                # Simple keyword search to pull relevant context lines
                keywords = ["xss", "sqli", "port", "header", "cors", "ip address", "token", "key", "disclosure", "owasp", "cve", "dns"]
                found_keywords = [k for k in keywords if k in prompt.lower() or k in system.lower()]
                
                with open(dataset_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if any(k in line.lower() for k in found_keywords):
                            context_snippets.append(line.strip())
                            if len(context_snippets) >= 20: # Expanded context capacity
                                break
            except Exception as e:
                logger.error(f"Error reading leaf corporate dataset: {e}")
        
        corp_context = "\n".join(context_snippets) if context_snippets else ""
        context_status = "FOUND" if corp_context else "MISSING_LOCAL_FALLBACK_TO_API"
        
        # 2. Check for Offline Mode (explicit environment flag or missing API key config)
        is_offline = os.environ.get("LEAF_AI_OFFLINE", "false").lower() == "true"
        openrouter_key = self.api_key or os.environ.get("OPENROUTER_API_KEY")
        if not openrouter_key:
            is_offline = True

        if is_offline:
            # Local rules-based RAG offline fallback (offline model weights removed)
            if corp_context:
                return f"[Leaf Security AI - Offline RAG Mode]\n(Matching from local corporate intelligence context):\n\n{corp_context[:800]}..."
            else:
                return "[Leaf Security AI - Offline Mode]\nOffline mode active but no matching local dataset context found. Please connect to the internet to run online API queries."

        # 3. Online path: Enrich and route
        # If context was missing locally, instruct the LLM to use its global cybersecurity knowledge base
        if context_status == "FOUND":
            enriched_prompt = f"""
[LEAF SECURITY CORPORATE THREAT INTEL CONTEXT]
{corp_context}
[END CONTEXT]

User Prompt: {prompt}
"""
        else:
            enriched_prompt = f"""
[LEAF SECURITY NOTICE]
No specific matching local company/threat context was found in the RAG dataset.
Please answer the prompt below using your global cybersecurity knowledge base and standard security practices.

User Prompt: {prompt}
"""

        # Route the enriched prompt directly to the configured API (OpenRouter/Gemini/etc.)
        openrouter_key = self.api_key or os.environ.get("OPENROUTER_API_KEY")
        if openrouter_key:
            try:
                headers = {
                    "Authorization": f"Bearer {openrouter_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/Jovinap/leafscan",
                    "X-Title": "Leaf Security AI Router"
                }
                body = {
                    "model": self.model if "local" not in self.api_url else "openrouter/free",
                    "messages": [
                        {"role": "system", "content": system or "You are the Leaf Security AI assistant."},
                        {"role": "user", "content": enriched_prompt}
                    ],
                    "temperature": 0.2
                }
                api_endpoint = self.api_url if "local" not in self.api_url else "https://openrouter.ai/api/v1/chat/completions"
                r = requests.post(api_endpoint, headers=headers, json=body, timeout=5)
                if r.ok:
                    return r.json()["choices"][0]["message"]["content"]
                else:
                    logger.warning(f"API query error: {r.status_code}")
            except Exception as e:
                logger.warning(f"Error connecting to user API: {e}. Falling back to offline RAG.")
                
        # Local RAG fallback if API fails or is not configured
        if corp_context:
            return f"[Leaf Security AI - Offline RAG Mode]\n(Answering from local context):\n\n{corp_context[:800]}..."
        return "[Leaf Security AI] No API key configured and no local dataset matches found. Set OPENROUTER_API_KEY or run config wizard."

    def _call_anthropic(self, prompt: str, system: str) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
            "temperature": 0.2
        }
        if system:
            body["system"] = system

        r = requests.post(self.api_url, headers=headers, json=body, timeout=20)
        if r.ok:
            return r.json()["content"][0]["text"]
        else:
            return f"Anthropic API Error: {r.status_code} - {r.text}"

    def _call_cohere(self, prompt: str, system: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        body = {
            "model": self.model,
            "message": prompt,
            "preamble": system,
            "temperature": 0.2
        }
        r = requests.post(self.api_url, headers=headers, json=body, timeout=20)
        if r.ok:
            return r.json()["text"]
        else:
            return f"Cohere API Error: {r.status_code} - {r.text}"
