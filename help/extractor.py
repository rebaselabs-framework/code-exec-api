"""Extract help metadata from FastAPI route objects.

Reads FastAPI's existing route metadata (docstrings, parameter annotations,
Pydantic models, response models) and formats it into EndpointHelp.
Zero duplication — the same source of truth as the API itself.
"""
from __future__ import annotations

import inspect
from typing import Any, get_args, get_origin

from fastapi import routing as fastapi_routing
from pydantic import BaseModel
from pydantic.fields import FieldInfo

from .models import AuthInfo, BodyInfo, EndpointHelp, Example, HelpMeta, ParameterInfo, RelatedEndpoint

__all__ = ["extract_endpoint_help"]

# Known auth dependency names (detect by function name convention)
_AUTH_DEP_NAMES = frozenset({"get_current_user", "require_auth", "verify_token", "api_key_auth", "authenticate"})

# Default auth info for unauthenticated endpoints
_NO_AUTH = AuthInfo(required=False, schemes=[], description="No authentication required")
_BEARER_AUTH = AuthInfo(
    required=True,
    schemes=["bearer"],
    description="API key as Bearer token in Authorization header",
)


def _python_type_to_str(annotation: Any) -> str:
    """Convert a Python type annotation to a readable string."""
    if annotation is None or annotation is inspect.Parameter.empty:
        return "string"

    origin = get_origin(annotation)
    args = get_args(annotation)

    # Handle Optional[X] → X | null
    if origin is type(None):
        return "null"

    # Handle Union / Optional
    if origin is not None and hasattr(origin, "__name__") and origin.__name__ == "Union":
        parts = [_python_type_to_str(a) for a in args if a is not type(None)]
        return " | ".join(parts)

    # Handle plain builtins
    name_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
        bytes: "bytes",
    }
    if annotation in name_map:
        return name_map[annotation]

    # Handle generic aliases like List[str], Dict[str, Any], Optional[str]
    if origin is not None:
        origin_name = getattr(origin, "__name__", str(origin))
        if args:
            args_str = ", ".join(_python_type_to_str(a) for a in args)
            return f"{origin_name}[{args_str}]"
        return origin_name

    # Pydantic model → use class name
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation.__name__

    return getattr(annotation, "__name__", str(annotation))


def _field_info_to_param(name: str, field: FieldInfo, annotation: Any) -> ParameterInfo:
    """Convert a Pydantic FieldInfo into a ParameterInfo."""
    type_str = _python_type_to_str(annotation)

    # Check if required
    required = field.is_required()

    # Default value
    default = None if required else field.default

    # Description
    description = field.description or f"The {name} parameter"

    # Constraints (ge, le, min_length, max_length, pattern)
    constraints_parts: list[str] = []
    if hasattr(field, "metadata"):
        for meta in field.metadata:
            if hasattr(meta, "ge"):
                constraints_parts.append(f">={meta.ge}")
            if hasattr(meta, "le"):
                constraints_parts.append(f"<={meta.le}")
            if hasattr(meta, "gt"):
                constraints_parts.append(f">{meta.gt}")
            if hasattr(meta, "lt"):
                constraints_parts.append(f"<{meta.lt}")
            if hasattr(meta, "min_length"):
                constraints_parts.append(f"min_length={meta.min_length}")
            if hasattr(meta, "max_length"):
                constraints_parts.append(f"max_length={meta.max_length}")
            if hasattr(meta, "pattern"):
                constraints_parts.append(f"pattern={meta.pattern}")

    constraints = ", ".join(constraints_parts) if constraints_parts else None

    return ParameterInfo(
        name=name,
        type=type_str,
        required=required,
        default=default,
        description=description,
        constraints=constraints,
    )


def _pydantic_model_to_body(model: type[BaseModel]) -> BodyInfo:
    """Convert a Pydantic model to BodyInfo by inspecting its fields."""
    fields: list[ParameterInfo] = []
    for field_name, field_info in model.model_fields.items():
        annotation = model.__annotations__.get(field_name)
        fields.append(_field_info_to_param(field_name, field_info, annotation))

    return BodyInfo(content_type="application/json", fields=fields)


def _has_auth_dependency(route: fastapi_routing.APIRoute) -> bool:
    """Detect if a route has auth-related dependencies by inspecting the dependency tree."""
    try:
        deps = list(route.dependencies or [])
        # Also check the endpoint's own function signature
        sig = inspect.signature(route.endpoint)
        for param in sig.parameters.values():
            if param.name in _AUTH_DEP_NAMES:
                return True
            # Check for Depends() with known auth callables
            if hasattr(param.default, "dependency"):
                dep_func = param.default.dependency
                dep_name = getattr(dep_func, "__name__", "")
                if dep_name in _AUTH_DEP_NAMES:
                    return True

        for dep in deps:
            if hasattr(dep, "dependency"):
                dep_name = getattr(dep.dependency, "__name__", "")
                if dep_name in _AUTH_DEP_NAMES:
                    return True
    except (ValueError, TypeError):
        pass
    return False


def _extract_docstring(func: Any) -> tuple[str, str]:
    """Return (summary, full_description) from a function's docstring."""
    doc = inspect.getdoc(func) or ""
    lines = doc.strip().splitlines()
    if not lines:
        return "", ""
    summary = lines[0].strip()
    description = "\n".join(lines).strip()
    return summary, description


def _get_body_model(route: fastapi_routing.APIRoute) -> type[BaseModel] | None:
    """Extract the Pydantic request model from a route, if any."""
    try:
        sig = inspect.signature(route.endpoint)
        for param in sig.parameters.values():
            annotation = param.annotation
            if (
                annotation is not inspect.Parameter.empty
                and isinstance(annotation, type)
                and issubclass(annotation, BaseModel)
            ):
                return annotation
    except (ValueError, TypeError):
        pass
    return None


def _extract_query_params(route: fastapi_routing.APIRoute) -> list[ParameterInfo]:
    """Extract query parameters from a route's endpoint signature."""
    params: list[ParameterInfo] = []
    try:
        sig = inspect.signature(route.endpoint)
        path_param_names = set()
        # Extract path parameter names from route path
        import re
        path_param_names = set(re.findall(r"\{(\w+)\}", route.path))

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "request", "response"):
                continue
            annotation = param.annotation
            if annotation is inspect.Parameter.empty:
                continue
            # Skip Pydantic model params (they're body)
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                continue
            # Skip Depends
            if hasattr(param.default, "dependency") or hasattr(param.default, "__class__") and param.default.__class__.__name__ == "FieldInfo":
                # Check if it's actually a Query() param
                pass
            # Skip path params
            if param_name in path_param_names:
                continue
            # Skip params that look like they have FastAPI injection defaults
            if hasattr(param.default, "__class__") and param.default.__class__.__name__ in ("Depends", "Security"):
                continue

            required = param.default is inspect.Parameter.empty
            default = None if required else param.default

            params.append(
                ParameterInfo(
                    name=param_name,
                    type=_python_type_to_str(annotation),
                    required=required,
                    default=default,
                    description=f"Query parameter: {param_name}",
                )
            )
    except (ValueError, TypeError):
        pass
    return params


def _extract_path_params(route: fastapi_routing.APIRoute) -> list[ParameterInfo]:
    """Extract path parameters from a route's path template."""
    import re
    params: list[ParameterInfo] = []
    path_params = re.findall(r"\{(\w+)\}", route.path)

    if not path_params:
        return params

    # Try to get annotations from endpoint signature
    try:
        sig = inspect.signature(route.endpoint)
        for param_name in path_params:
            if param_name in sig.parameters:
                param = sig.parameters[param_name]
                annotation = param.annotation
                type_str = _python_type_to_str(annotation) if annotation is not inspect.Parameter.empty else "string"
            else:
                type_str = "string"

            params.append(
                ParameterInfo(
                    name=param_name,
                    type=type_str,
                    required=True,
                    default=None,
                    description=f"Path parameter: {param_name}",
                )
            )
    except (ValueError, TypeError):
        for param_name in path_params:
            params.append(
                ParameterInfo(
                    name=param_name,
                    type="string",
                    required=True,
                    default=None,
                    description=f"Path parameter: {param_name}",
                )
            )

    return params


def _default_responses(method: str) -> dict[str, str]:
    """Return default response descriptions based on HTTP method."""
    base = {
        "400": "Invalid request — check parameters and format",
        "422": "Validation error — request body or query params failed validation",
        "500": "Internal server error",
    }
    if method in ("POST", "PUT", "PATCH"):
        base["200"] = "Success"
    else:
        base["200"] = "Success"
    return base


def extract_endpoint_help(route: fastapi_routing.APIRoute, method: str) -> EndpointHelp:
    """Extract a complete EndpointHelp from a FastAPI route.

    Reads docstrings, parameter annotations, Pydantic models, and any
    @help_meta metadata attached to the endpoint function.
    """
    endpoint_func = route.endpoint
    summary, description = _extract_docstring(endpoint_func)

    # Fall back to route.summary / route.description
    if not summary:
        summary = route.summary or f"{method} {route.path}"
    if not description:
        description = route.description or summary

    # Auth detection
    has_auth = _has_auth_dependency(route)
    decorator_meta: HelpMeta | None = getattr(endpoint_func, "_help_meta", None)

    if decorator_meta and decorator_meta.auth is not None:
        auth = decorator_meta.auth
    elif has_auth:
        auth = _BEARER_AUTH
    else:
        auth = _NO_AUTH

    # Path parameters
    path_params = _extract_path_params(route)

    # Body
    body_model = _get_body_model(route)
    body: BodyInfo | None = _pydantic_model_to_body(body_model) if body_model else None

    # Query parameters (only meaningful for GET/DELETE/HEAD)
    query_params = _extract_query_params(route) if method in ("GET", "DELETE", "HEAD") else []

    # Responses — merge defaults with decorator overrides
    responses = _default_responses(method)
    if decorator_meta and decorator_meta.responses:
        responses.update(decorator_meta.responses)

    # Examples and related from decorator
    examples: list[Example] = decorator_meta.examples if decorator_meta else []
    related: list[RelatedEndpoint] = decorator_meta.related if decorator_meta else []

    return EndpointHelp(
        method=method,
        path=route.path,
        summary=summary,
        description=description,
        auth=auth,
        parameters={
            "path": [p.model_dump() for p in path_params],
            "query": [p.model_dump() for p in query_params],
            "body": body.model_dump() if body else None,
        },
        responses=responses,
        examples=examples,
        related=related,
    )
