"""@help_meta decorator for enriching endpoint help with examples and related links."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .models import AuthInfo, Example, HelpMeta, RelatedEndpoint

__all__ = ["help_meta", "HelpExample", "RelatedEndpoint", "AuthInfo"]


# Re-export for convenience
HelpExample = Example


def help_meta(
    *,
    examples: list[Example] | None = None,
    related: list[RelatedEndpoint] | None = None,
    auth: AuthInfo | None = None,
    responses: dict[str, str] | None = None,
) -> Callable[[Any], Any]:
    """Attach extra help metadata to a FastAPI endpoint.

    Usage::

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
        async def my_endpoint(...):
            ...

    The decorator stores metadata on the function object so the extractor can
    find it when generating ?_help responses.
    """
    meta = HelpMeta(
        examples=examples or [],
        related=related or [],
        auth=auth,
        responses=responses or {},
    )

    def decorator(func: Any) -> Any:
        func._help_meta = meta
        return func

    return decorator
