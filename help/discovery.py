"""Service-level discovery — GET /_help returns the full endpoint catalog."""
from __future__ import annotations

import inspect

from fastapi import FastAPI, Request
from fastapi import routing as fastapi_routing

from .models import ServiceEndpointSummary, ServiceHelp

__all__ = ["build_service_help"]


def _route_summary(route: fastapi_routing.APIRoute) -> str:
    """Get a one-line summary from the route's summary or docstring."""
    if route.summary:
        return route.summary
    doc = inspect.getdoc(route.endpoint) or ""
    first_line = doc.strip().splitlines()[0] if doc.strip() else ""
    return first_line or f"{route.path}"


def build_service_help(app: FastAPI) -> ServiceHelp:
    """Build a ServiceHelp by iterating the FastAPI app's routes."""
    endpoints: list[ServiceEndpointSummary] = []

    for route in app.routes:
        if not isinstance(route, fastapi_routing.APIRoute):
            continue
        # Skip internal/utility routes
        if route.path in ("/_help", "/openapi.json", "/docs", "/redoc"):
            continue

        for method in sorted(route.methods or []):
            # Skip HEAD / OPTIONS (low value for discovery)
            if method in ("HEAD", "OPTIONS"):
                continue
            endpoints.append(
                ServiceEndpointSummary(
                    method=method,
                    path=route.path,
                    summary=_route_summary(route),
                )
            )

    return ServiceHelp(
        service=app.title,
        version=app.version,
        description=app.description or f"{app.title} API",
        endpoints=endpoints,
    )
