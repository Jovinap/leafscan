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
        if not self.enabled or not self.api_key:
            return "⚠️ AI integration is not configured or enabled."

        try:
            # 1. Handle Anthropic format separately
            if self.provider == "anthropic":
                return self._call_anthropic(prompt, system)

            # 2. Handle Cohere format separately
            if self.provider == "cohere" and "chat/completions" not in self.api_url:
                return self._call_cohere(prompt, system)

            # 3. Standard OpenAI-compatible format
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
