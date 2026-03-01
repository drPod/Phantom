"""Pydantic models for OSINT scan: Entity, Node, Edge, ScanConfig, ScanResult."""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    WALLET = "wallet"
    DOMAIN = "domain"
    IP = "ip"


class Entity(BaseModel):
    """An identity or identifier discovered during a scan."""

    type: EntityType
    value: str
    source: str = Field(..., description="Resolver or source that found this entity")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    depth: int = Field(ge=0, description="Hops from seed")

    def entity_key(self) -> str:
        """Canonical key for deduplication (normalized type:value)."""
        v = (str(self.value) if not isinstance(self.value, str) else self.value).strip().lower()
        if self.type == EntityType.EMAIL:
            v = v.lower()
        return f"{self.type.value}:{v}"


class Node(BaseModel):
    """Graph node representing an entity."""

    id: str = Field(..., description="Same as entity_key for the entity")
    type: EntityType
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    depth: int = 0


class Edge(BaseModel):
    """Directed edge between two nodes."""

    source: str = Field(..., description="Node id (entity_key)")
    target: str = Field(..., description="Node id (entity_key)")
    relationship: str = Field(default="linked_to")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class ScanConfig(BaseModel):
    """Limits and options for a scan."""

    max_entities: int = Field(default=500, ge=1, le=10_000)
    max_depth: int = Field(default=3, ge=0, le=10)
    timeout_minutes: int = Field(default=20, ge=1, le=120)
    demo_mode: bool = Field(default=False, description=(
        "When True, caps the scan at max_depth=1, max_entities=50, timeout=3 min, "
        "and skips GPU post-processing to keep total wall-clock time under 3 minutes "
        "for live demonstrations."
    ))

    def model_post_init(self, __context: object) -> None:
        """If demo_mode is set, enforce fast limits."""
        if self.demo_mode:
            self.max_depth = min(self.max_depth, 1)
            self.max_entities = min(self.max_entities, 50)
            self.timeout_minutes = min(self.timeout_minutes, 3)


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanResult(BaseModel):
    """Result stored per scan_id (status + optional graph)."""

    status: ScanStatus
    graph: dict[str, Any] | None = Field(default=None, description="nodes + edges when completed")
    report: str | None = Field(default=None, description="Final intelligence report markdown")
    error: str | None = Field(default=None, description="Error message when status is failed")
    entities_seen: int = 0
    depth_reached: int = 0


# Request/response schemas for API
class SeedRequest(BaseModel):
    type: EntityType
    value: str
    email: str | None = None
    real_name: str | None = Field(default=None, description=(
        "Known real name of the target (e.g. 'Darsh Poddar'). "
        "Used to anchor identity and reject mismatches faster."
    ))


class ScanRequest(BaseModel):
    seed: SeedRequest
    config: ScanConfig | None = None
    demo_mode: bool = Field(default=False, description=(
        "Shorthand to enable demo_mode without constructing a full config object. "
        "Caps scan at max_depth=1, max_entities=50, timeout=3 min, skips GPU post-processing."
    ))

    def model_post_init(self, __context: object) -> None:
        """Propagate demo_mode shorthand into config."""
        if self.demo_mode:
            if self.config is None:
                self.config = ScanConfig(demo_mode=True)
            else:
                self.config.demo_mode = True


class ScanResponse(BaseModel):
    scan_id: str


class StatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    entities_seen: int = 0
    depth_reached: int = 0
    error: str | None = None
    report: str | None = None


class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
