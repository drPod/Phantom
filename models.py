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
        v = self.value.strip().lower()
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


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResult(BaseModel):
    """Result stored per scan_id (status + optional graph)."""

    status: ScanStatus
    graph: dict[str, Any] | None = Field(default=None, description="nodes + edges when completed")
    error: str | None = Field(default=None, description="Error message when status is failed")
    entities_seen: int = 0
    depth_reached: int = 0


# Request/response schemas for API
class SeedRequest(BaseModel):
    type: EntityType
    value: str


class ScanRequest(BaseModel):
    seed: SeedRequest
    config: ScanConfig | None = None


class ScanResponse(BaseModel):
    scan_id: str


class StatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    entities_seen: int = 0
    depth_reached: int = 0
    error: str | None = None


class GraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
