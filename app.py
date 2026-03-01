"""Modal app definition, image, and secrets for OSINT recon."""

from pathlib import Path

import modal

# Local package dir for add_local_dir (replaces deprecated modal.Mount).
_local_dir = Path(__file__).resolve().parent

# Base image for API, orchestrator, and resolvers (CPU).
# Phase 2 can add a separate GPU image for extraction.
image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install(
        "requests~=2.32",
        "httpx[http2]~=0.27",
        "aiohttp~=3.11",
        "beautifulsoup4~=4.12",
        "networkx~=3.3",
        "pydantic~=2.9",
        "fastapi[standard]~=0.115",
        "emailrep",
        "leakcheck~=2.0.0",
        "dnspython~=2.7",
        "lxml~=5.3",
        "disposable-email-domains",
        "anthropic~=0.49",
        "tenacity~=8.2",
    )
    .env({"PYTHONPATH": "/root/osint_recon"})
    .add_local_dir(_local_dir, remote_path="/root/osint_recon")
)

# All API keys from Modal Secret; resolvers read via os.environ.
osint_secret = modal.Secret.from_name("osint-keys")

app = modal.App(
    "osint-recon",
    image=image,
)

# Register all Modal functions and ASGI app (order can matter for mounts/imports).
import api  # noqa: F401
import orchestrator  # noqa: F401
import resolvers.username  # noqa: F401
import resolvers.email  # noqa: F401
import resolvers.domain  # noqa: F401
import resolvers.username_enum  # noqa: F401
import resolvers.breach  # noqa: F401
import resolvers.social  # noqa: F401
import resolvers.identity_correlator  # noqa: F401
import resolvers.phone  # noqa: F401
import resolvers.wallet  # noqa: F401
import inference.extractor  # noqa: F401
import agent.state  # noqa: F401
import telemetry.exporter  # noqa: F401
import telemetry.evaluator  # noqa: F401
import telemetry.proposer  # noqa: F401
import telemetry.manifest  # noqa: F401
import telemetry.changelog  # noqa: F401
