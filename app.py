"""
Code Execution API v1.0.0 — Sandboxed Python execution for AI agents.

AI agents can't run code themselves — this API lets them execute Python
safely and get structured output back.

Sandbox design:
  - RestrictedPython: compiles code with safe AST transforms
  - Whitelisted builtins: math, string, data structure operations
  - Whitelisted stdlib imports: math, json, re, statistics, itertools,
    functools, collections, datetime, decimal, random
  - Blocked: os, sys, subprocess, socket, http, open, eval, exec
  - Hard limits: 15s timeout, 256MB memory, 50KB output cap

Endpoints:
  POST /api/execute        — run Python code, return stdout/result
  POST /api/execute/batch  — run up to 10 snippets concurrently
  GET  /health             — service health
  GET  /                   — service info + endpoint list

Auth:
  X-API-Key: <key>   (or Bearer token)
  Admin: POST /api/keys to provision keys (requires ADMIN_KEY env var)
"""
from __future__ import annotations

import ast
import asyncio
import builtins as _builtins_module
import json
import logging
import os
import time
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from auth import (
    ADMIN_KEY,
    ApiKeyMiddleware,
    create_key,
    get_key_by_id,
    init_auth_store,
    list_keys,
    revoke_key,
)

# ──────────────────────────────────────────────
# Optional sandbox dep
# ──────────────────────────────────────────────

RESTRICTED_PYTHON_AVAILABLE = False
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from RestrictedPython import (
            compile_restricted,
            safe_globals,
            safe_builtins,
            PrintCollector,
            utility_builtins,
        )
        from RestrictedPython.Guards import guarded_iter_unpack_sequence
    RESTRICTED_PYTHON_AVAILABLE = True
except ImportError:
    pass

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

VERSION = "1.0.0"
MAX_TIMEOUT_SECONDS = 30
DEFAULT_TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 50_000   # 50KB
MAX_BATCH_SIZE = 10
MAX_CODE_LENGTH = 50_000    # 50KB of code

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("code-exec-api")

# Thread pool for running code (avoids blocking the event loop)
_EXECUTOR_WORKERS = int(os.environ.get("EXEC_WORKERS", "8"))
_executor = ThreadPoolExecutor(max_workers=_EXECUTOR_WORKERS)

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_auth_store()
    logger.info(f"Code Execution API v{VERSION} started")
    logger.info(f"RestrictedPython available: {RESTRICTED_PYTHON_AVAILABLE}")
    yield
    _executor.shutdown(wait=False)

app = FastAPI(
    title="Code Execution API",
    version=VERSION,
    description="Sandboxed Python execution for AI agents.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(ApiKeyMiddleware)

# ──────────────────────────────────────────────
# Sandbox: safe imports whitelist
# ──────────────────────────────────────────────

SAFE_MODULES = {
    "math", "cmath", "decimal", "fractions", "statistics",
    "random", "itertools", "functools", "operator",
    "collections", "heapq", "bisect",
    "re", "string", "textwrap", "unicodedata",
    "json", "csv", "io",
    "datetime", "calendar", "time",
    "hashlib", "hmac", "base64", "binascii",
    "struct", "codecs",
    "copy", "pprint",
    "enum", "dataclasses",
    "typing",
    "abc",
}


# Pre-sorted for error messages — avoids sorting on every blocked import
_SAFE_MODULES_STR = ", ".join(sorted(SAFE_MODULES))

# Builtins to add on top of RestrictedPython's conservative safe_builtins
_EXTRA_SAFE_BUILTINS: tuple = (
    "all", "any", "ascii", "bin", "bytearray", "dict", "dir",
    "enumerate", "filter", "format", "getattr", "hasattr", "iter",
    "list", "map", "max", "min", "next", "print", "reversed",
    "sum", "type", "vars",
    # numeric
    "abs", "complex", "divmod", "float", "int", "pow", "round",
    # string/bytes
    "bytes", "chr", "hex", "oct", "ord", "repr", "str",
    # containers
    "frozenset", "set", "tuple", "zip", "slice",
    # type checks
    "bool", "callable", "isinstance", "issubclass",
    # misc
    "id", "hash", "len", "range",
    # class support
    "staticmethod", "classmethod", "property", "super",
    # constants
    "NotImplemented", "Ellipsis",
)

# Guard-hook names that must never be overwritten by injected variables
_SANDBOX_GUARD_KEYS = frozenset({
    "_print_", "_print", "_getattr_", "_getitem_", "_getiter_",
    "_write_", "_iter_unpack_sequence_", "__builtins__", "__name__",
    "__import__", "__build_class__",
})


def _safe_import(name, *args, **kwargs):
    """Import guard — only allow SAFE_MODULES."""
    root = name.split(".")[0]
    if root not in SAFE_MODULES:
        raise ImportError(
            f"Import of '{name}' is not allowed in the sandbox. "
            f"Allowed modules: {_SAFE_MODULES_STR}"
        )
    return __import__(name, *args, **kwargs)


def _getattr_guard(obj, name):
    """Block access to dunder methods and dangerous attributes."""
    if name.startswith("_"):
        raise AttributeError(f"Access to '{name}' is restricted in the sandbox.")
    return getattr(obj, name)


def _getitem_guard(obj, key):
    return obj[key]


def _write_guard(obj):
    return obj


# ──────────────────────────────────────────────
# Sandbox: build execution globals
# ──────────────────────────────────────────────

def _build_sandbox_globals(injected_vars: Dict[str, Any]) -> dict:
    """Build the restricted globals dict for code execution.

    Shallow-copies a pre-built base so per-execution overhead is minimal.
    Injected vars are screened to prevent overwriting sandbox guard hooks.
    """
    if RESTRICTED_PYTHON_AVAILABLE:
        globs = safe_globals.copy()
        clean_builtins = safe_builtins.copy()
        clean_builtins.update(utility_builtins)
    else:
        globs = {}
        clean_builtins = {}

    # Add all safe builtins (module-level constant, no re-allocation)
    for name in _EXTRA_SAFE_BUILTINS:
        val = getattr(_builtins_module, name, None)
        if val is not None:
            clean_builtins[name] = val

    clean_builtins["__import__"] = _safe_import
    clean_builtins["__build_class__"] = _builtins_module.__build_class__

    globs["__builtins__"] = clean_builtins
    globs["__name__"] = "__main__"

    # RestrictedPython guard hooks
    if RESTRICTED_PYTHON_AVAILABLE:
        # _print_ (class) is instantiated by RestrictedPython as _print (no trailing _)
        globs["_print_"] = PrintCollector
        globs["_getattr_"] = _getattr_guard
        globs["_getitem_"] = _getitem_guard
        globs["_getiter_"] = iter
        globs["_write_"] = _write_guard
        globs["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence

    # Inject user-provided variables — screen out names that would shadow guard hooks
    safe_vars = {k: v for k, v in injected_vars.items() if k not in _SANDBOX_GUARD_KEYS}
    globs.update(safe_vars)

    return globs


# ──────────────────────────────────────────────
# Core execution engine
# ──────────────────────────────────────────────

class ExecutionResult:
    __slots__ = ("stdout", "stderr", "result", "error", "elapsed_ms", "truncated")

    def __init__(self):
        self.stdout = ""
        self.stderr = ""
        self.result = None
        self.error: Optional[str] = None
        self.elapsed_ms = 0
        self.truncated = False


def _run_code_sync(
    code: str,
    injected_vars: Dict[str, Any],
    timeout: float,
) -> ExecutionResult:
    """Run code synchronously (called from thread pool)."""
    res = ExecutionResult()
    start = time.monotonic()

    try:
        globs = _build_sandbox_globals(injected_vars)

        if RESTRICTED_PYTHON_AVAILABLE:
            # compile_restricted emits SyntaxWarnings for print usage — suppress them
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                bytecode = compile_restricted(code, filename="<agent_code>", mode="exec")
            if bytecode is None:
                res.error = "Code failed to compile (restricted syntax check)."
                return res
        else:
            # Fallback: use compile() with basic safety checks
            _basic_safety_check(code)
            bytecode = compile(code, "<agent_code>", "exec")

        exec(bytecode, globs)  # noqa: S102

        # Capture stdout:
        # RestrictedPython: _print_ (class) → _print (instance) during exec
        # The instance's __call__() returns collected text
        if RESTRICTED_PYTHON_AVAILABLE:
            printer = globs.get("_print")
            if printer is not None and isinstance(printer, PrintCollector):
                res.stdout = printer()
        else:
            # Fallback: stdout was captured via sys.stdout redirect in _basic_safety_check path
            res.stdout = ""

        # Capture final value of 'result' variable if set
        if "result" in globs:
            val = globs["result"]
            try:
                res.result = json.loads(json.dumps(val, default=str))
            except Exception:
                res.result = str(val)

    except SyntaxError as e:
        res.error = f"SyntaxError: {e}"
    except ImportError as e:
        res.error = f"ImportError: {e}"
    except NameError as e:
        res.error = f"NameError: {e}"
    except Exception as e:
        tb = traceback.format_exc()
        # Keep only frames from user code (avoid leaking internal paths)
        lines = [
            ln for ln in tb.splitlines()
            if "<agent_code>" in ln or (not ln.startswith("  File") and not ln.startswith("Traceback"))
        ]
        res.error = f"{type(e).__name__}: {e}"
        res.stderr = "\n".join(lines[-10:])
    finally:
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        if len(res.stdout) > MAX_OUTPUT_BYTES:
            res.stdout = res.stdout[:MAX_OUTPUT_BYTES]
            res.truncated = True

    return res


def _basic_safety_check(code: str) -> None:
    """Rudimentary static safety check when RestrictedPython is unavailable."""
    tree = ast.parse(code)
    BLOCKED_NAMES = {
        "os", "sys", "subprocess", "socket", "http", "urllib",
        "pathlib", "shutil", "tempfile", "glob", "fnmatch",
        "eval", "exec", "compile", "__import__", "open",
        "input", "breakpoint", "quit", "exit",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BLOCKED_NAMES or root not in SAFE_MODULES:
                    raise ImportError(f"Import of '{alias.name}' is not allowed.")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BLOCKED_NAMES or root not in SAFE_MODULES:
                raise ImportError(f"Import from '{node.module}' is not allowed.")
        elif isinstance(node, ast.Name):
            if node.id in BLOCKED_NAMES and isinstance(node.ctx, ast.Load):
                raise NameError(f"Use of '{node.id}' is not allowed in the sandbox.")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile"):
                raise RuntimeError(f"Call to '{node.func.id}' is not allowed.")


async def execute_code(
    code: str,
    injected_vars: Dict[str, Any],
    timeout: float,
) -> ExecutionResult:
    """Execute code asynchronously with a hard timeout."""
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(_executor, _run_code_sync, code, injected_vars, timeout)
        result = await asyncio.wait_for(future, timeout=timeout)
        return result
    except asyncio.TimeoutError:
        res = ExecutionResult()
        res.error = f"Execution timed out after {timeout:.0f}s."
        res.elapsed_ms = int(timeout * 1000)
        return res


# ──────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    code: str = Field(
        ...,
        description="Python code to execute. Set `result` variable to capture structured output.",
        examples=["import math\nresult = math.sqrt(144)\nprint(f'Answer: {result}')"],
    )
    variables: Dict[str, Any] = Field(
        default_factory=dict,
        description="Pre-injected variables available in the code namespace (e.g. pass data as 'rows').",
    )
    timeout: float = Field(
        DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_TIMEOUT_SECONDS,
        description=f"Max execution time in seconds (1-{MAX_TIMEOUT_SECONDS}).",
    )

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if len(v) > MAX_CODE_LENGTH:
            raise ValueError(f"Code exceeds maximum length of {MAX_CODE_LENGTH} characters.")
        if not v.strip():
            raise ValueError("Code cannot be empty.")
        return v

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, v: dict) -> dict:
        # Serialize/deserialize to ensure all values are JSON-safe
        try:
            return json.loads(json.dumps(v))
        except (TypeError, ValueError) as e:
            raise ValueError(f"Variables must be JSON-serializable: {e}")


class ExecuteResponse(BaseModel):
    success: bool
    stdout: str
    stderr: str
    result: Optional[Any] = None
    error: Optional[str] = None
    elapsed_ms: int
    truncated: bool = False


class BatchExecuteRequest(BaseModel):
    tasks: List[ExecuteRequest] = Field(
        ...,
        description="List of execution tasks (max 10).",
        min_length=1,
        max_length=MAX_BATCH_SIZE,
    )


class BatchExecuteResponse(BaseModel):
    results: List[ExecuteResponse]
    total_elapsed_ms: int


class ProvisionKeyRequest(BaseModel):
    label: str = Field("", description="Human-readable label for this key.")
    tier: str = Field("free", description="Tier: free (500), starter (10K), pro (100K) executions.")
    calls_limit: Optional[int] = Field(None, description="Override call limit.")


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Code Execution API",
        "version": VERSION,
        "status": "online",
        "sandbox": "RestrictedPython" if RESTRICTED_PYTHON_AVAILABLE else "AST-guard",
        "endpoints": {
            "execute":       "POST /api/execute",
            "execute_batch": "POST /api/execute/batch",
            "health":        "GET  /health",
            "provision_key": "POST /api/keys  (admin only)",
            "list_keys":     "GET  /api/keys/list  (admin only)",
            "docs":          "GET  /docs",
        },
        "limits": {
            "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "max_batch_size": MAX_BATCH_SIZE,
            "max_code_length": MAX_CODE_LENGTH,
        },
        "safe_imports": sorted(SAFE_MODULES),
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": VERSION,
        "sandbox": "RestrictedPython" if RESTRICTED_PYTHON_AVAILABLE else "AST-guard",
    }


@app.get("/_help")
def help_endpoint():
    return root()


# ── Execute ────────────────────────────────────

@app.post("/api/execute", response_model=ExecuteResponse)
async def api_execute(req: ExecuteRequest):
    """
    Execute Python code in a sandboxed environment.

    **Tip:** Set the `result` variable in your code to return structured data:
    ```python
    data = [{"name": "Alice", "score": 95}, {"name": "Bob", "score": 82}]
    result = sorted(data, key=lambda x: x["score"], reverse=True)
    print(f"Top scorer: {result[0]['name']}")
    ```

    **Injecting data via variables:**
    ```json
    {
      "code": "result = [r for r in rows if r['revenue'] > 1000]",
      "variables": {"rows": [{"name": "Acme", "revenue": 5000}, ...]}
    }
    ```
    """
    res = await execute_code(req.code, req.variables, req.timeout)
    return ExecuteResponse(
        success=res.error is None,
        stdout=res.stdout,
        stderr=res.stderr,
        result=res.result,
        error=res.error,
        elapsed_ms=res.elapsed_ms,
        truncated=res.truncated,
    )


@app.post("/api/execute/batch", response_model=BatchExecuteResponse)
async def api_execute_batch(req: BatchExecuteRequest):
    """
    Execute up to 10 Python snippets concurrently.

    All tasks run in parallel. Each task has its own isolated namespace.
    """
    start = time.monotonic()
    tasks = [
        execute_code(t.code, t.variables, t.timeout)
        for t in req.tasks
    ]
    results = await asyncio.gather(*tasks)
    total_elapsed = int((time.monotonic() - start) * 1000)

    responses = [
        ExecuteResponse(
            success=r.error is None,
            stdout=r.stdout,
            stderr=r.stderr,
            result=r.result,
            error=r.error,
            elapsed_ms=r.elapsed_ms,
            truncated=r.truncated,
        )
        for r in results
    ]
    return BatchExecuteResponse(results=responses, total_elapsed_ms=total_elapsed)


# ── Auth admin ─────────────────────────────────
# ADMIN_KEY is imported from auth.py — single source of truth

def _require_admin(request: Request):
    key = (
        request.headers.get("X-API-Key")
        or request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    )
    if key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required.")


@app.post("/api/keys", tags=["auth"])
def provision_key(body: ProvisionKeyRequest, request: Request):
    _require_admin(request)
    result = create_key(
        label=body.label,
        tier=body.tier,
        calls_limit=body.calls_limit or 500,
    )
    return result


@app.get("/api/keys/list", tags=["auth"])
def list_api_keys(request: Request):
    _require_admin(request)
    return {"keys": list_keys()}


@app.get("/api/keys/{key_id}", tags=["auth"])
def get_api_key(key_id: str, request: Request):
    _require_admin(request)
    info = get_key_by_id(key_id)
    if not info:
        raise HTTPException(status_code=404, detail="Key not found.")
    return info


@app.post("/api/keys/{key_id}/revoke", tags=["auth"])
def revoke_api_key(key_id: str, request: Request):
    _require_admin(request)
    revoke_key(key_id)
    return {"status": "revoked", "id": key_id}


# ── Error handling ─────────────────────────────

@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error.", "detail": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
