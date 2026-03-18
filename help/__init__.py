"""Self-Describing API Convention — help package.

Drop this package into any FastAPI project and every endpoint becomes
self-describing via ?_help query parameter.

Quick start::

    from fastapi import FastAPI
    from help import HelpMiddleware

    app = FastAPI()
    app.add_middleware(HelpMiddleware)

    # That's it. Now every endpoint responds to ?_help.

For enriching endpoints with examples and related links::

    from help import help_meta, HelpExample, RelatedEndpoint

    @router.post("/transfers")
    @help_meta(
        examples=[
            HelpExample(
                description="Transform JSON to CSV",
                request={"body": {"input_format": "json", "output_format": "csv", "data": "..."}},
                response={"status": 200, "body": {"success": True, "output": "..."}},
            )
        ],
        related=[RelatedEndpoint(method="GET", path="/api/formats", summary="List supported formats")],
    )
    async def create_transfer(...):
        ...

For service-level discovery, add the /_help route::

    from help import build_service_help

    @app.get("/_help")
    async def service_help(request: Request):
        return build_service_help(request.app)
"""

from .decorator import AuthInfo, HelpExample, RelatedEndpoint, help_meta
from .discovery import build_service_help
from .middleware import HelpMiddleware
from .models import BodyInfo, EndpointHelp, ParameterInfo, ServiceHelp

__all__ = [
    # Middleware
    "HelpMiddleware",
    # Decorator
    "help_meta",
    "HelpExample",
    "RelatedEndpoint",
    "AuthInfo",
    # Discovery
    "build_service_help",
    # Models
    "EndpointHelp",
    "ServiceHelp",
    "ParameterInfo",
    "BodyInfo",
]
