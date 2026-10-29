"""Runs inside the target project's own interpreter -- ``python -I shim.py <repo> <entry>`` -- as the
platform's half of a subprocess target (``purpleteam.targets.subprocess``). Standard library only: the
target's environment has no purpleteam in it, and ``-I`` keeps this file's folder off ``sys.path`` so
nothing here can shadow the target's own imports.

It speaks JSON lines with the platform. stdout carries only protocol messages (the target's own prints
are moved to stderr); stdin carries the platform's answers. Before every tool runs the platform decides
(``authorize``); every tool result, the request and the final reply are screened by it. Nothing here
decides anything: the policy never enters the target's process.
"""

import functools
import importlib
import inspect
import json
import os
import re
import sys
import threading

PROTOCOL, sys.stdout = sys.stdout, sys.stderr
_LOCK = threading.Lock()  # a framework may run tools on several threads; one question and answer at a time
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_INPUT_FIELDS = ("messages", "input", "question", "query", "request", "message", "prompt", "topic", "task")


def emit(message):
    PROTOCOL.write(json.dumps(message, default=str) + "\n")
    PROTOCOL.flush()


def ask(message):
    with _LOCK:
        emit(message)
        line = sys.stdin.readline()
    if not line:
        raise SystemExit("the platform closed the channel")
    return json.loads(line)


def load(entry):
    module, _, attr = entry.partition(":")
    obj = importlib.import_module(module)
    for part in filter(None, attr.split(".")):
        obj = getattr(obj, part)
    if inspect.isclass(obj):  # e.g. a CrewAI @CrewBase class: an instance builds the crew
        instance = obj()
        return instance.crew() if callable(getattr(instance, "crew", None)) else instance
    if inspect.isfunction(obj) and not inspect.signature(obj).parameters:  # a factory that builds the app
        return obj()
    return obj


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(text)).strip("_")[:64] or "agent"


def _is_tool(value):
    return (not inspect.isclass(value) and isinstance(getattr(value, "name", None), str)
            and isinstance(getattr(value, "description", None), str)
            and (callable(getattr(value, "func", None)) or callable(getattr(value, "_run", None))))


def discover(app, repo):
    """(tools as {id: (agent, tool)}, agents) -- from the app's own agents, then any tool object defined
    in the project's own modules."""
    tools, agents = {}, []
    for agent in getattr(app, "agents", None) or []:
        name = _slug(getattr(agent, "role", None) or getattr(agent, "name", None) or "agent")
        prompt = "\n".join(str(getattr(agent, field, "") or "") for field in ("role", "goal", "backstory",
                                                                               "system_prompt", "instructions"))
        held = [t for t in (getattr(agent, "tools", None) or []) if _is_tool(t)]
        agents.append({"name": name, "prompt": prompt.strip(), "tools": [t.name for t in held]})
        for tool in held:
            tools.setdefault(id(tool), (name, tool))
    for module in list(sys.modules.values()):
        file = getattr(module, "__file__", None)
        if not file or not os.path.abspath(file).startswith(repo):
            continue
        for value in list(vars(module).values()):
            if _is_tool(value):
                tools.setdefault(id(value), (module.__name__.rsplit(".", 1)[-1], value))
    return tools, agents


def _bind(fn, args, kwargs):
    try:
        bound = dict(inspect.signature(fn).bind_partial(*args, **kwargs).arguments)
    except (TypeError, ValueError):
        bound = dict(kwargs)
    for noise in ("self", "run_manager", "callbacks"):
        bound.pop(noise, None)
    return bound


def _guarded(agent, name, fn):
    @functools.wraps(fn)
    def run(*args, **kwargs):
        call = _bind(fn, args, kwargs)
        verdict = ask({"type": "authorize", "agent": agent, "tool": name, "args": call})
        if not verdict.get("allow"):
            return f"Blocked by policy: {verdict.get('reason', '')}"
        result = fn(*args, **kwargs)
        screened = ask({"type": "screen", "agent": agent, "text": str(result), "source": "tool_result"})
        text = screened.get("text", f"Blocked by policy: {screened.get('blocked', '')}")
        emit({"type": "call", "agent": agent, "tool": name, "args": call, "result": text[:2000]})
        return result if text == str(result) else text
    return run


def wrap(tools):
    for agent, tool in tools.values():
        if callable(getattr(tool, "func", None)):
            object.__setattr__(tool, "func", _guarded(agent, tool.name, tool.func))
        else:
            object.__setattr__(tool, "_run", _guarded(agent, tool.name, tool._run))


def _source(tool):
    fn = getattr(tool, "func", None) or getattr(tool, "_run", None)
    try:
        return f"{os.path.basename(inspect.getsourcefile(fn))}:{inspect.getsourcelines(fn)[1]}"
    except (TypeError, OSError):
        return "?"


def profile(tools, agents):
    described = []
    for agent, tool in tools.values():
        args = getattr(tool, "args", None)
        described.append({"name": tool.name, "description": tool.description, "agent": agent,
                          "args": args if isinstance(args, dict) else {}, "source": _source(tool)})
    return {"type": "profile", "tools": described, "agents": agents}


def _input_shape(app):
    """How this app takes a request: by a named field of its input schema, or as plain text."""
    schema = getattr(app, "input_schema", None)
    try:
        fields = set(schema.model_json_schema().get("properties", {})) if schema is not None else set()
    except Exception:
        fields = set()
    return next((field for field in _INPUT_FIELDS if field in fields), None)


def _unrun_calls(result):
    """Tool calls the model asked for that never got a result -- an approval pause, a refusal by the app itself
    -- read from a LangChain/LangGraph message history. The platform judges them as attempts."""
    messages = result.get("messages") if isinstance(result, dict) else None
    if not isinstance(messages, list):
        return []
    answered = {getattr(m, "tool_call_id", None) for m in messages}
    return [{"tool": c.get("name"), "args": c.get("args") if isinstance(c.get("args"), dict) else {}}
            for m in messages for c in (getattr(m, "tool_calls", None) or [])
            if isinstance(c, dict) and c.get("name") and c.get("id") not in answered]


def invoke(app, request):
    if callable(getattr(app, "kickoff", None)):  # a crew: every {placeholder} its tasks and agents use
        texts = [str(getattr(item, field, "") or "") for item in [*getattr(app, "tasks", []), *getattr(app, "agents", [])]
                 for field in ("description", "expected_output", "role", "goal", "backstory")]
        inputs = {name: request for text in texts for name in _PLACEHOLDER.findall(text)}
        result = app.kickoff(inputs=inputs)
    elif callable(getattr(app, "invoke", None)):
        field = _input_shape(app)
        payload = {"messages": [("user", request)]} if field == "messages" else {field: request} if field else request
        result = app.invoke(payload)
    else:
        result = app(request)
    return _text(result), _unrun_calls(result)


def _text(result):
    if isinstance(result, dict) and result.get("messages"):
        last = result["messages"][-1]
        return str(getattr(last, "content", last))
    for attr in ("raw", "output", "content"):
        if isinstance(getattr(result, attr, None), str):
            return getattr(result, attr)
    if isinstance(result, dict) and isinstance(result.get("output"), str):
        return result["output"]
    return str(result)


def main():
    repo, entry = os.path.abspath(sys.argv[1]), sys.argv[2]
    for root in (os.path.join(repo, "src"), repo):
        if os.path.isdir(root):
            sys.path.insert(0, root)
    os.chdir(repo)
    app = load(entry)
    tools, agents = discover(app, repo)
    wrap(tools)
    emit({"type": "ready"})
    for line in sys.stdin:
        message = json.loads(line)
        if message["op"] == "profile":
            emit(profile(tools, agents))
        elif message["op"] == "send":
            screened = ask({"type": "screen", "agent": "input", "text": message["request"], "source": "input"})
            if "text" not in screened:
                emit({"type": "reply", "reply": f"Blocked by policy: {screened.get('blocked', '')}"})
                continue
            try:
                reply, proposed = invoke(app, screened["text"])
                out = ask({"type": "screen", "agent": "output", "text": reply, "source": "output"})
                emit({"type": "reply", "reply": out.get("text", f"Blocked by policy: {out.get('blocked', '')}"),
                      "proposed": proposed})
            except Exception as error:  # the type only: a message could carry target data
                emit({"type": "reply", "reply": "", "error": type(error).__name__})
        elif message["op"] == "quit":
            break


if __name__ == "__main__":
    main()
