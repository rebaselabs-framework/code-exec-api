"""Pydantic models for the self-describing API help system.

Every ?_help response is structured using these models.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ParameterInfo(BaseModel):
    """Describes a single parameter (path, query, or body field)."""

    name: str
    type: str = Field(description="e.g. 'string', 'integer', 'boolean', or enum values like 'full | incremental'")
    required: bool
    default: Any | None = None
    description: str
    constraints: str | None = None


class BodyInfo(BaseModel):
    """Describes the request body."""

    content_type: str = "application/json"
    fields: list[ParameterInfo] = Field(default_factory=list)


class AuthInfo(BaseModel):
    """Authentication requirements for an endpoint."""

    required: bool
    schemes: list[str] = Field(default_factory=list)
    description: str


class Example(BaseModel):
    """A complete request/response example."""

    description: str
    request: dict[str, Any]
    response: dict[str, Any]


class RelatedEndpoint(BaseModel):
    """A related endpoint the caller might need next."""

    method: str
    path: str
    summary: str


class EndpointHelp(BaseModel):
    """Full self-describing help for a single endpoint."""

    method: str
    path: str
    summary: str
    description: str
    auth: AuthInfo | None = None
    parameters: dict[str, Any] = Field(default_factory=lambda: {"path": [], "query": [], "body": None})
    responses: dict[str, str] = Field(default_factory=dict)
    examples: list[Example] = Field(default_factory=list)
    related: list[RelatedEndpoint] = Field(default_factory=list)


class ServiceEndpointSummary(BaseModel):
    """One-line summary of an endpoint for service-level discovery."""

    method: str
    path: str
    summary: str


class ServiceHelp(BaseModel):
    """Service-level discovery — the table of contents for the API."""

    service: str
    version: str
    description: str
    endpoints: list[ServiceEndpointSummary] = Field(default_factory=list)


class HelpMeta(BaseModel):
    """Extra metadata attached to an endpoint via @help_meta decorator."""

    examples: list[Example] = Field(default_factory=list)
    related: list[RelatedEndpoint] = Field(default_factory=list)
    auth: AuthInfo | None = None
    responses: dict[str, str] = Field(default_factory=dict)
