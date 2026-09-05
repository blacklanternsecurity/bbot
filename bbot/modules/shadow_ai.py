import re
from typing import Literal

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.base import BaseModule


class shadow_ai(BaseModule):
    """Surface an organization's AI footprint.

    Two complementary signals:

      1. Third-party AI/LLM services the organization touches, discovered from
         hostnames and harvested links (emitted as TECHNOLOGY).
      2. Self-hosted AI runtimes reachable from outside, discovered from open
         ports (emitted as FINDING). An unauthenticated local inference server or
         agent gateway on the perimeter is a real exposure: most ship with no
         authentication by default.

      3. AI agent gateway control interfaces, fingerprinted from HTTP responses
         that another module has already fetched (emitted as FINDING). Port
         matching alone misses these -- a large share of exposed gateways sit
         behind 80/443, where the port number reveals nothing.

    This is the passive/safe detection tier. It complements the invasive Nuclei
    templates BBOT already ships (e.g. mcp-inspector-detect, ollama panels) which
    the `nuclei` module runs opt-in: this module surfaces the exposure in a default
    scan, nuclei confirms exploitability when explicitly enabled.
    """

    watched_events = ["DNS_NAME", "URL_UNVERIFIED", "OPEN_TCP_PORT", "HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY", "FINDING"]
    flags = ["passive", "safe"]
    meta = {
        "description": "Detect shadow AI: third-party AI/LLM services and exposed self-hosted AI runtimes",
        "created_date": "2026-09-04",
        "author": "@repins267",
    }

    class Config(BaseModuleConfig):
        categories: list[str] = Field(
            default_factory=list,
            description=(
                "Only report these categories (empty list = all). Valid values: assistant, "
                "ai-platform, code-assistant, agent-platform, media-genai, productivity"
            ),
        )
        min_risk: Literal["low", "medium", "high"] = Field("low", description="Minimum risk level to report")
        check_ports: bool = Field(True, description="Report self-hosted AI runtimes discovered on open ports")

    _risk_order = {"low": 0, "medium": 1, "high": 2}

    # Keys are matched against each parent of the event's host, so a registrable domain
    # ("openai.com") also matches its subdomains, while a fully-qualified key
    # ("gemini.google.com") matches only that host and below. This keeps broad shared
    # domains such as google.com from matching everything under them.
    #
    # Risk rationale:
    #   high   - autonomous execution (agents that drive a shell, browser or IDE),
    #            consumer-only services with no enterprise controls, or providers subject
    #            to mandatory state data-access regimes
    #   medium - established provider with an enterprise offering (the default)
    #   low    - enterprise-managed, where the customer controls data residency
    #
    # domain: (provider, category, risk)
    ai_domains = {
        # --- general-purpose assistants ---
        "openai.com": ("OpenAI", "assistant", "medium"),
        "chatgpt.com": ("OpenAI", "assistant", "medium"),
        "anthropic.com": ("Anthropic", "assistant", "medium"),
        "claude.ai": ("Anthropic", "assistant", "medium"),
        "gemini.google.com": ("Google", "assistant", "medium"),
        "copilot.microsoft.com": ("Microsoft", "assistant", "medium"),
        "perplexity.ai": ("Perplexity", "assistant", "medium"),
        "mistral.ai": ("Mistral", "assistant", "medium"),
        "cohere.com": ("Cohere", "assistant", "medium"),
        "x.ai": ("xAI", "assistant", "medium"),
        "poe.com": ("Poe", "assistant", "medium"),
        "character.ai": ("Character.AI", "assistant", "high"),
        "deepseek.com": ("DeepSeek", "assistant", "high"),
        "moonshot.cn": ("Moonshot", "assistant", "high"),
        "bigmodel.cn": ("Zhipu", "assistant", "high"),
        "doubao.com": ("ByteDance", "assistant", "high"),
        "01.ai": ("01.AI", "assistant", "high"),
        # --- model hosting / inference platforms ---
        "openai.azure.com": ("Azure OpenAI", "ai-platform", "low"),
        "huggingface.co": ("Hugging Face", "ai-platform", "medium"),
        "replicate.com": ("Replicate", "ai-platform", "medium"),
        "together.ai": ("Together AI", "ai-platform", "medium"),
        "groq.com": ("Groq", "ai-platform", "medium"),
        "fireworks.ai": ("Fireworks AI", "ai-platform", "medium"),
        "openrouter.ai": ("OpenRouter", "ai-platform", "medium"),
        "anyscale.com": ("Anyscale", "ai-platform", "medium"),
        "runpod.io": ("RunPod", "ai-platform", "medium"),
        "modal.com": ("Modal", "ai-platform", "medium"),
        "baseten.co": ("Baseten", "ai-platform", "medium"),
        "dashscope.aliyuncs.com": ("Alibaba Qwen", "ai-platform", "high"),
        # --- coding assistants ---
        "cursor.com": ("Cursor", "code-assistant", "medium"),
        "cursor.sh": ("Cursor", "code-assistant", "medium"),
        "codeium.com": ("Codeium", "code-assistant", "medium"),
        "windsurf.com": ("Windsurf", "code-assistant", "medium"),
        "tabnine.com": ("Tabnine", "code-assistant", "medium"),
        "sourcegraph.com": ("Sourcegraph Cody", "code-assistant", "medium"),
        "qodo.ai": ("Qodo", "code-assistant", "medium"),
        "codium.ai": ("Qodo", "code-assistant", "medium"),
        "phind.com": ("Phind", "code-assistant", "medium"),
        "blackbox.ai": ("Blackbox AI", "code-assistant", "medium"),
        "v0.dev": ("Vercel v0", "code-assistant", "medium"),
        "lovable.dev": ("Lovable", "code-assistant", "medium"),
        "bolt.new": ("Bolt", "code-assistant", "medium"),
        # --- agent platforms and autonomous frameworks ---
        # Rated high: these execute code, drive a browser, or act on a user's behalf,
        # so a misconfiguration or supply-chain compromise has a far larger blast radius
        # than a chat interface.
        "all-hands.dev": ("OpenHands", "agent-platform", "high"),
        "crewai.com": ("CrewAI", "agent-platform", "high"),
        "flowiseai.com": ("Flowise", "agent-platform", "high"),
        "dify.ai": ("Dify", "agent-platform", "high"),
        "agno.com": ("Agno", "agent-platform", "high"),
        "e2b.dev": ("E2B", "agent-platform", "high"),
        "browserbase.com": ("Browserbase", "agent-platform", "high"),
        "lindy.ai": ("Lindy", "agent-platform", "high"),
        "relevanceai.com": ("Relevance AI", "agent-platform", "high"),
        "langchain.com": ("LangChain", "agent-platform", "medium"),
        "llamaindex.ai": ("LlamaIndex", "agent-platform", "medium"),
        "n8n.io": ("n8n", "agent-platform", "medium"),
        "zapier.com": ("Zapier", "agent-platform", "medium"),
        # --- generative media ---
        "midjourney.com": ("Midjourney", "media-genai", "medium"),
        "stability.ai": ("Stability AI", "media-genai", "medium"),
        "runwayml.com": ("Runway", "media-genai", "medium"),
        "elevenlabs.io": ("ElevenLabs", "media-genai", "medium"),
        "leonardo.ai": ("Leonardo AI", "media-genai", "medium"),
        "suno.com": ("Suno", "media-genai", "medium"),
        "heygen.com": ("HeyGen", "media-genai", "medium"),
        "synthesia.io": ("Synthesia", "media-genai", "medium"),
        "descript.com": ("Descript", "media-genai", "medium"),
        "civitai.com": ("CivitAI", "media-genai", "high"),
        "seaart.ai": ("SeaArt", "media-genai", "high"),
        # --- AI productivity / knowledge ---
        "otter.ai": ("Otter.ai", "productivity", "medium"),
        "fireflies.ai": ("Fireflies.ai", "productivity", "medium"),
        "gamma.app": ("Gamma", "productivity", "medium"),
        "jasper.ai": ("Jasper", "productivity", "medium"),
        "copy.ai": ("Copy.ai", "productivity", "medium"),
        "writesonic.com": ("Writesonic", "productivity", "medium"),
        "you.com": ("You.com", "productivity", "medium"),
        "grammarly.com": ("Grammarly", "productivity", "medium"),
    }

    # Default listening ports of self-hosted AI runtimes.
    #
    # Deliberately limited to DISTINCTIVE ports. Generic ports commonly used by these
    # projects (3000, 5000, 8000, 8080) are excluded on purpose: they are dominated by
    # unrelated services and would bury real findings in false positives. Confidence
    # reflects how specific the port is to the runtime; none of these are confirmed
    # without an active check, which this module does not perform (it stays passive).
    #
    # port: (runtime, kind, severity, confidence, cves)
    # Runtimes that have an HTTP title fingerprint below (OpenClaw, MCP Inspector, Langflow)
    # are intentionally NOT here -- the title match is CONFIRMED and avoids a duplicate
    # low-confidence port finding for the same host.
    ai_ports = {
        11434: ("Ollama", "inference API", "HIGH", "MEDIUM", []),
        11435: ("Ollama", "inference API", "HIGH", "LOW", []),
        1234: ("LM Studio", "inference API", "HIGH", "LOW", []),
        1337: ("Jan", "inference API", "HIGH", "LOW", []),
        8188: ("ComfyUI", "media-generation UI", "MEDIUM", "LOW", []),
        3001: ("AnythingLLM", "RAG/chat UI", "MEDIUM", "LOW", []),
        8265: ("Ray", "AI compute dashboard", "HIGH", "MEDIUM", ["CVE-2023-48022"]),
    }

    # Control interfaces of self-hosted AI agent gateways, fingerprinted from a response
    # body that another module already fetched. This is the reliable signal: only about
    # half of exposed gateways listen on their documented port, the rest sit behind 80,
    # 443 or a reverse proxy where a port number tells you nothing.
    #
    # Exposed AI control UIs, fingerprinted from a response body another module already
    # fetched -- reliable across ports/proxies where a port number tells you nothing.
    # Descriptions are kept short (CVE lives in the FINDING's cves field); the detail is
    # one clause on impact. Detection is title-only; no exploit path is touched.
    #
    # slug: (title pattern, display label, cves, one-line impact)
    agent_gateways = {
        "openclaw": (
            r"<title>[^<]*\b(?:OpenClaw|Clawdbot|Moltbot)\s+Control\b[^<]*</title>",
            "OpenClaw agent gateway",
            ["CVE-2026-25253"],
            "grants control of an AI agent's tools, browser and stored provider credentials",
        ),
        "mcp-inspector": (
            r"<title>[^<]*MCP Inspector[^<]*</title>",
            "MCP Inspector",
            ["CVE-2025-49596"],
            "MCP dev tool; pre-0.14.1 proxy allows unauthenticated browser-driven RCE",
        ),
        "langflow": (
            r"<title>[^<]*Langflow[^<]*</title>",
            "Langflow",
            ["CVE-2025-3248"],
            "visual LLM-app builder; pre-1.3.0 /api/v1/validate/code allows unauthenticated RCE",
        ),
    }

    async def setup(self):
        self.min_risk = self._risk_order[self.config.get("min_risk", "low")]

        valid_categories = {c for _, c, _ in self.ai_domains.values()}
        self.categories = {str(c).strip().lower() for c in self.config.get("categories", []) or []}
        invalid = self.categories - valid_categories
        if invalid:
            return False, f"Invalid categories: {','.join(sorted(invalid))}"

        self.check_ports = self.config.get("check_ports", True)
        self._gateway_patterns = {
            slug: (re.compile(pattern, re.I), label, cves, detail)
            for slug, (pattern, label, cves, detail) in self.agent_gateways.items()
        }
        return True

    def _reportable(self, category, risk):
        if self.categories and category not in self.categories:
            return False
        return self._risk_order[risk] >= self.min_risk

    def _lookup(self, host):
        """Return (matched_domain, (provider, category, risk)) for a host, else None."""
        for parent in self.helpers.domain_parents(host, include_self=True):
            entry = self.ai_domains.get(parent)
            if entry is not None:
                return parent, entry
        return None

    async def handle_event(self, event):
        if event.type == "OPEN_TCP_PORT":
            if self.check_ports:
                await self._handle_port(event)
        elif event.type == "HTTP_RESPONSE":
            await self._handle_http_response(event)
        else:
            await self._handle_host(event)

    async def _handle_http_response(self, event):
        body = event.body or ""
        if not body:
            return
        for slug, (pattern, label, cves, detail) in self._gateway_patterns.items():
            if not pattern.search(body):
                continue
            url = event.data.get("url", "")
            await self.emit_event(
                {"host": str(event.host), "technology": slug, "url": url},
                "TECHNOLOGY",
                parent=event,
                context=f"{{module}} identified {{event.type}}: {label} at {url}",
            )
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "name": f"Exposed AI interface: {label}",
                    "description": f"Exposed {label} at {url} ({detail}). Title fingerprint; exploit path not touched.",
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "cves": cves,
                },
                "FINDING",
                parent=event,
                context=f"{{module}} found {{event.type}}: exposed {label} at {url}",
            )
            return

    async def _handle_host(self, event):
        host = str(event.host or "").lower()
        # IPs carry no namespace to match against
        if not host or self.helpers.is_ip(host):
            return
        match = self._lookup(host)
        if match is None:
            return
        domain, (provider, category, risk) = match
        if not self._reportable(category, risk):
            return

        data = {"host": host, "technology": provider.lower()}
        if event.type == "URL_UNVERIFIED":
            data["url"] = event.data
        await self.emit_event(
            data,
            "TECHNOLOGY",
            parent=event,
            context=f"{{module}} identified {{event.type}}: {provider} ({category}, {risk} risk) via {domain}",
        )

    async def _handle_port(self, event):
        runtime = self.ai_ports.get(event.port)
        if runtime is None:
            return
        name, kind, severity, confidence, cves = runtime
        data = {
            "host": str(event.host),
            "name": f"Exposed AI runtime: {name}",
            "description": (
                f"Possible {name} {kind} on port {event.port} (inferred from the port alone; "
                f"not confirmed). These typically ship unauthenticated."
            ),
            "severity": severity,
            "confidence": confidence,
        }
        if cves:
            data["cves"] = cves
        await self.emit_event(
            data,
            "FINDING",
            parent=event,
            context=f"{{module}} flagged {{event.type}}: possible {name} on port {event.port}",
        )
