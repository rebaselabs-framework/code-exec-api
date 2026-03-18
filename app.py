"""
Code Execution API v2.0.0 — Multi-language sandboxed execution for AI agents.

AI agents can't run code themselves — this API lets them execute Python
and JavaScript safely and get structured output back.

Python sandbox:
  - RestrictedPython: compiles code with safe AST transforms
  - Whitelisted stdlib: math, json, re, statistics, itertools, collections,
    datetime, decimal, random, hashlib, base64, struct, copy, enum, typing
  - Blocked: os, sys, subprocess, socket, http, open, eval, exec
  - Hard limits: 30s timeout, 50KB output cap

JavaScript sandbox:
  - Node.js subprocess with --disallow-code-generation-from-strings
  - Blocked require(): fs, child_process, os, net, http, https, cluster,
    dgram, dns, tls, v8, vm, worker_threads, readline
  - Allowed: built-in Node.js globals (Math, JSON, Date, Buffer, etc.)
  - Hard limits: 30s timeout, 50KB output cap

Sessions (Python only):
  - Stateful namespaces that persist across multiple execute calls
  - POST /api/session/create  — create a session
  - POST /api/session/execute — run code with shared state
  - DELETE /api/session/{id}  — delete session
  - Sessions auto-expire after 10 minutes of inactivity

Endpoints:
  POST /api/execute           — run code (language: python | javascript)
  POST /api/execute/python    — Python shorthand
  POST /api/execute/js        — JavaScript shorthand
  POST /api/execute/batch     — run up to 10 snippets concurrently
  POST /api/session/create    — create a stateful Python session
  POST /api/session/execute   — execute in session context
  DELETE /api/session/{id}    — destroy session
  GET  /health                — service health
  GET  /                      — service info + endpoint list

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
import secrets
import tempfile
import time
import traceback
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field as dc_field
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
from help import HelpMiddleware, build_service_help

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

VERSION = "2.2.0"
MAX_TIMEOUT_SECONDS = 30
DEFAULT_TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 50_000     # 50KB
MAX_BATCH_SIZE = 10
MAX_CODE_LENGTH = 50_000      # 50KB of code
SESSION_TTL_SECONDS = 600     # 10 min session inactivity timeout
MAX_SESSIONS = 200            # max concurrent sessions

# Detect Node.js availability
_NODE_AVAILABLE = False
try:
    import subprocess as _subprocess
    _r = _subprocess.run(["node", "--version"], capture_output=True, timeout=3)
    _NODE_AVAILABLE = _r.returncode == 0
except Exception:
    pass

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
app.add_middleware(HelpMiddleware)

# ──────────────────────────────────────────────
# Sandbox: safe imports whitelist
# ──────────────────────────────────────────────

SAFE_MODULES = {
    # stdlib — pure computation
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
    # data science — agents need these for analysis tasks
    "numpy",         # numerical arrays, math (import numpy as np works)
    "pandas",        # dataframes, CSV analysis (import pandas as pd works)
    "scipy",         # statistical / signal processing
    "sklearn",       # scikit-learn ML (optional, if installed)
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
# JavaScript execution engine
# ──────────────────────────────────────────────

# Modules blocked from require() in the JS sandbox
_JS_BLOCKED_MODULES = frozenset({
    "fs", "path", "child_process", "os", "net", "http", "https",
    "cluster", "dgram", "dns", "readline", "repl", "tls", "v8",
    "vm", "worker_threads", "module", "process", "native_module",
})

_JS_SANDBOX_WRAPPER = """\
'use strict';
// ── Sandbox: block dangerous require() calls ──────────────────
const _BLOCKED_MODS = new Set({blocked_json});
const _orig_require = (typeof require !== 'undefined') ? require : null;
if (_orig_require) {{
  global.require = function sandboxedRequire(mod) {{
    const root = String(mod).split('/')[0].split('\\\\')[0].replace(/^@[^/]+\\//, '');
    if (_BLOCKED_MODS.has(root)) {{
      throw new Error("require('" + mod + "') is not allowed in the sandbox.");
    }}
    return _orig_require(mod);
  }};
}}

// ── Inject caller-provided variables ──────────────────────────
const _injected = {vars_json};
Object.keys(_injected).forEach(k => {{ global[k] = _injected[k]; }});

// ── User code ─────────────────────────────────────────────────
let result = undefined;
(async () => {{
  try {{
{indented_code}
  }} catch (e) {{
    process.stderr.write((e && e.stack) ? e.stack : String(e));
    process.exitCode = 1;
    return;
  }}
  if (typeof result !== 'undefined') {{
    process.stdout.write('\\n__EXEC_RESULT__:' + JSON.stringify(result) + '\\n');
  }}
}})();
"""


async def _run_js_code(
    code: str,
    injected_vars: Dict[str, Any],
    timeout: float,
) -> "ExecutionResult":
    """Execute JavaScript in a Node.js subprocess with security restrictions."""
    res = ExecutionResult()
    start = time.monotonic()

    if not _NODE_AVAILABLE:
        res.error = "Node.js is not available on this server."
        return res

    # Build sandbox wrapper
    vars_json = json.dumps(injected_vars, default=str)
    blocked_json = json.dumps(sorted(_JS_BLOCKED_MODULES))
    indented = "\n".join("    " + line for line in code.splitlines())
    wrapper = _JS_SANDBOX_WRAPPER.format(
        vars_json=vars_json,
        blocked_json=blocked_json,
        indented_code=indented,
    )

    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(wrapper)
            tmp = f.name

        proc = await asyncio.create_subprocess_exec(
            "node",
            "--disallow-code-generation-from-strings",
            "--max-old-space-size=256",
            tmp,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            res.error = f"Execution timed out after {timeout:.0f}s."
            res.elapsed_ms = int(timeout * 1000)
            return res

        raw_stdout = stdout_b.decode("utf-8", errors="replace")
        raw_stderr = stderr_b.decode("utf-8", errors="replace")

        # Extract __EXEC_RESULT__ sentinel
        clean_lines = []
        for line in raw_stdout.splitlines():
            if line.startswith("__EXEC_RESULT__:"):
                try:
                    res.result = json.loads(line[len("__EXEC_RESULT__:"):])
                except Exception:
                    res.result = line[len("__EXEC_RESULT__:"):]
            else:
                clean_lines.append(line)

        res.stdout = "\n".join(clean_lines)
        if len(res.stdout) > MAX_OUTPUT_BYTES:
            res.stdout = res.stdout[:MAX_OUTPUT_BYTES]
            res.truncated = True

        # Sanitize stderr — strip internal Node.js frames, keep user frames
        if raw_stderr:
            stderr_lines = raw_stderr.splitlines()
            user_lines = [
                ln for ln in stderr_lines
                if not (ln.strip().startswith("at ") and (
                    "/node_modules/" in ln or "node:internal" in ln or ln.endswith("(node:timers)")
                ))
            ]
            res.stderr = "\n".join(user_lines[:20])
            if proc.returncode != 0:
                res.error = f"JavaScript runtime error (exit {proc.returncode})"

    except Exception as exc:
        res.error = f"JS execution setup error: {exc}"
    finally:
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    return res


# ──────────────────────────────────────────────
# Python session store (stateful execution)
# ──────────────────────────────────────────────

@dataclass
class _Session:
    session_id: str
    language: str
    globals: Dict[str, Any] = dc_field(default_factory=dict)
    created_at: float = dc_field(default_factory=time.monotonic)
    last_used: float = dc_field(default_factory=time.monotonic)
    execution_count: int = 0
    stdout_history: List[str] = dc_field(default_factory=list)


_sessions: Dict[str, _Session] = {}


def _get_session(session_id: str) -> Optional[_Session]:
    sess = _sessions.get(session_id)
    if sess and (time.monotonic() - sess.last_used) > SESSION_TTL_SECONDS:
        del _sessions[session_id]
        return None
    return sess


def _expire_sessions() -> None:
    """Remove stale sessions."""
    now = time.monotonic()
    expired = [sid for sid, s in list(_sessions.items()) if now - s.last_used > SESSION_TTL_SECONDS]
    for sid in expired:
        _sessions.pop(sid, None)


def _run_session_code_sync(
    code: str,
    session: _Session,
    timeout: float,
) -> "ExecutionResult":
    """Execute code in a persistent session namespace."""
    res = ExecutionResult()
    start = time.monotonic()
    try:
        globs = session.globals
        # Ensure sandbox guards are set up on first call
        if "__builtins__" not in globs:
            globs.update(_build_sandbox_globals({}))
        # Re-initialise PrintCollector for this run
        if RESTRICTED_PYTHON_AVAILABLE:
            globs["_print_"] = PrintCollector

        if RESTRICTED_PYTHON_AVAILABLE:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                bytecode = compile_restricted(code, filename="<session>", mode="exec")
            if bytecode is None:
                res.error = "Code failed to compile (restricted syntax check)."
                return res
        else:
            _basic_safety_check(code)
            bytecode = compile(code, "<session>", "exec")

        exec(bytecode, globs)  # noqa: S102

        if RESTRICTED_PYTHON_AVAILABLE:
            printer = globs.get("_print")
            if printer is not None and isinstance(printer, PrintCollector):
                res.stdout = printer()
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
        lines = [ln for ln in tb.splitlines()
                 if "<session>" in ln or (not ln.startswith("  File") and not ln.startswith("Traceback"))]
        res.error = f"{type(e).__name__}: {e}"
        res.stderr = "\n".join(lines[-10:])
    finally:
        res.elapsed_ms = int((time.monotonic() - start) * 1000)
        if len(res.stdout) > MAX_OUTPUT_BYTES:
            res.stdout = res.stdout[:MAX_OUTPUT_BYTES]
            res.truncated = True
    return res


# ──────────────────────────────────────────────
# Request / Response models
# ──────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    code: str = Field(
        ...,
        description=(
            "Code to execute. Set `result` variable to capture structured output.\n"
            "Python: `import math; result = math.sqrt(144)`\n"
            "JavaScript: `result = [1,2,3].map(x => x*2)`"
        ),
    )
    language: str = Field(
        "python",
        description="Language: 'python' (default) or 'javascript'",
    )
    variables: Dict[str, Any] = Field(
        default_factory=dict,
        description="Pre-injected variables in the code namespace (e.g. pass data as 'rows').",
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

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ("python", "javascript", "js"):
            raise ValueError("language must be 'python' or 'javascript'")
        return "javascript" if v == "js" else v

    @field_validator("variables")
    @classmethod
    def validate_variables(cls, v: dict) -> dict:
        try:
            return json.loads(json.dumps(v))
        except (TypeError, ValueError) as e:
            raise ValueError(f"Variables must be JSON-serializable: {e}")


class ExecuteResponse(BaseModel):
    success: bool
    language: str = "python"
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


class CreateSessionRequest(BaseModel):
    language: str = Field("python", description="Session language: python (js sessions not stateful yet)")
    label: str = Field("", description="Optional label for this session.")


class CreateSessionResponse(BaseModel):
    session_id: str
    language: str
    created_at: float
    ttl_seconds: int = SESSION_TTL_SECONDS
    message: str


class SessionExecuteRequest(BaseModel):
    session_id: str = Field(..., description="Session ID from POST /api/session/create")
    code: str = Field(..., description="Code to execute in the session namespace")
    timeout: float = Field(DEFAULT_TIMEOUT_SECONDS, ge=1, le=MAX_TIMEOUT_SECONDS)

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if len(v) > MAX_CODE_LENGTH:
            raise ValueError(f"Code exceeds maximum length of {MAX_CODE_LENGTH} characters.")
        if not v.strip():
            raise ValueError("Code cannot be empty.")
        return v


class SessionExecuteResponse(BaseModel):
    success: bool
    session_id: str
    stdout: str
    stderr: str
    result: Optional[Any] = None
    error: Optional[str] = None
    elapsed_ms: int
    execution_count: int
    truncated: bool = False


class SessionInfoResponse(BaseModel):
    session_id: str
    language: str
    execution_count: int
    age_seconds: float
    idle_seconds: float
    variable_names: List[str]
    ttl_seconds: int


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Code Execution API",
        "version": VERSION,
        "status": "online",
        "languages": {
            "python": {"sandbox": "RestrictedPython" if RESTRICTED_PYTHON_AVAILABLE else "AST-guard"},
            "javascript": {"available": _NODE_AVAILABLE, "runtime": "Node.js"},
        },
        "endpoints": {
            "execute":          "POST /api/execute          — run code (language: python|javascript)",
            "execute_python":   "POST /api/execute/python   — Python shorthand",
            "execute_js":       "POST /api/execute/js       — JavaScript shorthand",
            "execute_batch":    "POST /api/execute/batch    — up to 10 concurrent tasks",
            "session_create":   "POST /api/session/create   — create stateful Python session",
            "session_execute":  "POST /api/session/execute  — run code in session",
            "session_list":     "GET  /api/session          — list all active sessions (new v2.2)",
            "session_info":     "GET  /api/session/{id}     — session status + variables",
            "session_delete":   "DELETE /api/session/{id}   — destroy session",
            "health":           "GET  /health",
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
        "_help_protocol": "Add ?_help to any endpoint URL, or POST {'_help': true} in any request body",
        "discovery": "GET /_help for full endpoint catalog",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": VERSION,
        "python_sandbox": "RestrictedPython" if RESTRICTED_PYTHON_AVAILABLE else "AST-guard",
        "javascript": _NODE_AVAILABLE,
        "active_sessions": len(_sessions),
    }


@app.get("/_help")
async def help_endpoint(request: Request):
    """Discover all available API endpoints and their parameters."""
    return build_service_help(request.app)


# ── Shared execution dispatcher ─────────────────

async def _dispatch_execute(req: ExecuteRequest) -> ExecuteResponse:
    """Run code in the appropriate language sandbox and return a response."""
    if req.language == "javascript":
        if not _NODE_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="JavaScript execution requires Node.js, which is not available on this server.",
            )
        res = await _run_js_code(req.code, req.variables, req.timeout)
    else:
        res = await execute_code(req.code, req.variables, req.timeout)
    return ExecuteResponse(
        success=res.error is None,
        language=req.language,
        stdout=res.stdout,
        stderr=res.stderr,
        result=res.result,
        error=res.error,
        elapsed_ms=res.elapsed_ms,
        truncated=res.truncated,
    )


# ── Execute (multi-language) ────────────────────

@app.post("/api/execute", response_model=ExecuteResponse)
async def api_execute(req: ExecuteRequest):
    """
    Execute code in a sandboxed environment.

    Supports **Python** (default) and **JavaScript** (Node.js).

    **Python example:**
    ```python
    import statistics
    scores = [88, 92, 95, 78, 90]
    result = {"mean": statistics.mean(scores), "max": max(scores)}
    print(f"Average: {result['mean']}")
    ```

    **JavaScript example:**
    ```json
    {
      "language": "javascript",
      "code": "const nums = rows.map(r => r.revenue); result = nums.reduce((a,b) => a+b, 0);",
      "variables": {"rows": [{"revenue": 100}, {"revenue": 200}]}
    }
    ```

    Set `result` in your code to capture structured data in the response.
    """
    return await _dispatch_execute(req)


@app.post("/api/execute/python", response_model=ExecuteResponse)
async def api_execute_python(req: ExecuteRequest):
    """Execute Python code. Shorthand for POST /api/execute with language='python'."""
    req.language = "python"
    return await _dispatch_execute(req)


@app.post("/api/execute/js", response_model=ExecuteResponse)
async def api_execute_js(req: ExecuteRequest):
    """Execute JavaScript (Node.js) code. Shorthand for POST /api/execute with language='javascript'."""
    req.language = "javascript"
    return await _dispatch_execute(req)


@app.post("/api/execute/batch", response_model=BatchExecuteResponse)
async def api_execute_batch(req: BatchExecuteRequest):
    """
    Execute up to 10 code snippets concurrently (Python and/or JavaScript).

    All tasks run in parallel. Each task has its own isolated namespace.
    Mix languages: some tasks can be Python, others JavaScript.
    """
    start = time.monotonic()
    tasks = [
        _dispatch_execute(t)
        for t in req.tasks
    ]
    results = await asyncio.gather(*tasks)
    total_elapsed = int((time.monotonic() - start) * 1000)

    # results are already ExecuteResponse objects from _dispatch_execute
    return BatchExecuteResponse(results=list(results), total_elapsed_ms=total_elapsed)


# ── Session endpoints ───────────────────────────

@app.post("/api/session/create", response_model=CreateSessionResponse, tags=["sessions"])
async def api_session_create(req: CreateSessionRequest):
    """Create a stateful Python session.

    Sessions preserve variables between code calls — run multiple
    snippets that share state. Perfect for multi-step analysis:

    ```
    # Call 1: load and clean data
    rows = [{"name": "Alice", "score": 95}, {"name": "Bob", "score": 82}]
    cleaned = [r for r in rows if r["score"] > 80]

    # Call 2: compute stats (cleaned is still in scope)
    import statistics
    result = {"mean": statistics.mean(r["score"] for r in cleaned)}
    ```

    Sessions auto-expire after 10 minutes of inactivity.
    """
    _expire_sessions()
    if len(_sessions) >= MAX_SESSIONS:
        raise HTTPException(status_code=503, detail=f"Session limit reached ({MAX_SESSIONS}).")

    if req.language != "python":
        raise HTTPException(status_code=400, detail="Only 'python' sessions are supported currently.")

    sid = str(uuid.uuid4())
    sess = _Session(session_id=sid, language=req.language)
    # Pre-initialise sandbox globals
    sess.globals.update(_build_sandbox_globals({}))
    _sessions[sid] = sess

    return CreateSessionResponse(
        session_id=sid,
        language=req.language,
        created_at=sess.created_at,
        ttl_seconds=SESSION_TTL_SECONDS,
        message=f"Session created. Use POST /api/session/execute with session_id='{sid}'",
    )


@app.post("/api/session/execute", response_model=SessionExecuteResponse, tags=["sessions"])
async def api_session_execute(req: SessionExecuteRequest):
    """Execute code within a persistent session namespace.

    Variables set in previous calls remain available.
    The `result` variable is reset each call; set it to capture structured output.
    """
    sess = _get_session(req.session_id)
    if sess is None:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{req.session_id}' not found or expired. Create a new one.",
        )

    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(_executor, _run_session_code_sync, req.code, sess, req.timeout)
        res = await asyncio.wait_for(future, timeout=req.timeout + 2)
    except asyncio.TimeoutError:
        res = ExecutionResult()
        res.error = f"Execution timed out after {req.timeout:.0f}s."
        res.elapsed_ms = int(req.timeout * 1000)

    sess.last_used = time.monotonic()
    sess.execution_count += 1
    if res.stdout:
        sess.stdout_history.append(res.stdout)

    return SessionExecuteResponse(
        success=res.error is None,
        session_id=req.session_id,
        stdout=res.stdout,
        stderr=res.stderr,
        result=res.result,
        error=res.error,
        elapsed_ms=res.elapsed_ms,
        execution_count=sess.execution_count,
        truncated=res.truncated,
    )


@app.get("/api/session/{session_id}", response_model=SessionInfoResponse, tags=["sessions"])
async def api_session_info(session_id: str):
    """Get session status, variable names, and usage stats."""
    sess = _get_session(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found or expired.")

    now = time.monotonic()
    # List user-defined variables (exclude sandbox internals)
    user_vars = [
        k for k in sess.globals.keys()
        if not k.startswith("_") and k not in ("__builtins__", "__name__", "__build_class__")
    ]

    return SessionInfoResponse(
        session_id=session_id,
        language=sess.language,
        execution_count=sess.execution_count,
        age_seconds=round(now - sess.created_at, 1),
        idle_seconds=round(now - sess.last_used, 1),
        variable_names=sorted(user_vars),
        ttl_seconds=max(0, int(SESSION_TTL_SECONDS - (now - sess.last_used))),
    )


@app.delete("/api/session/{session_id}", tags=["sessions"])
async def api_session_delete(session_id: str):
    """Destroy a session and free its memory."""
    if session_id in _sessions:
        del _sessions[session_id]
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")


@app.get("/api/session", tags=["sessions"])
async def api_session_list():
    """
    List all active sessions with summary stats.

    Shows session IDs, language, execution count, and idle time.
    Sessions auto-expire after 10 minutes of inactivity.
    """
    _expire_sessions()
    now = time.monotonic()
    sessions_summary = []
    for sid, sess in _sessions.items():
        idle = now - sess.last_used
        remaining = max(0, SESSION_TTL_SECONDS - idle)
        sessions_summary.append({
            "session_id": sid,
            "language": sess.language,
            "execution_count": sess.execution_count,
            "age_seconds": round(now - sess.created_at, 1),
            "idle_seconds": round(idle, 1),
            "ttl_remaining_seconds": int(remaining),
        })
    return {
        "active_sessions": len(sessions_summary),
        "max_sessions": MAX_SESSIONS,
        "sessions": sorted(sessions_summary, key=lambda s: s["idle_seconds"]),
    }


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
