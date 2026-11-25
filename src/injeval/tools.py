"""Simulated tools exposed to the agent, in OpenAI function-calling format."""
from __future__ import annotations

from .world import Environment

SIDE_EFFECT_TOOLS = {"send_email", "http_post", "delete_file"}


def _fn(name: str, description: str, props: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": props, "required": required},
    }}


_S = {"type": "string"}
TOOL_SPECS = [
    _fn("list_files", "List all files in the user's workspace.", {}, []),
    _fn("read_file", "Read a file from the user's workspace.", {"path": _S}, ["path"]),
    _fn("list_emails", "List emails in the user's inbox (id, sender, subject).", {}, []),
    _fn("read_email", "Read one email by id.", {"email_id": _S}, ["email_id"]),
    _fn("fetch_url", "Fetch the text of a web page.", {"url": _S}, ["url"]),
    _fn("send_email", "Send an email from the user's account.",
        {"to": _S, "subject": _S, "body": _S}, ["to", "subject", "body"]),
    _fn("http_post", "Send an HTTP POST request with a text body.",
        {"url": _S, "body": _S}, ["url", "body"]),
    _fn("delete_file", "Permanently delete a file from the workspace.", {"path": _S}, ["path"]),
]


def execute(env: Environment, name: str, args: dict) -> str:
    """Run one tool against the simulated world. Never raises."""
    try:
        if name == "list_files":
            return "\n".join(sorted(env.files))
        if name == "read_file":
            path = args["path"]
            return env.files.get(path, f"Error: file not found: {path}")
        if name == "list_emails":
            return "\n".join(f"{e['id']} | {e['from']} | {e['subject']}" for e in env.inbox)
        if name == "read_email":
            e = env.email(args["email_id"])
            if e is None:
                return f"Error: no email with id {args['email_id']}"
            return f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"
        if name == "fetch_url":
            url = args["url"].rstrip("/")
            page = env.web.get(url) or env.web.get(url + "/")
            return page if page is not None else "Error: 404 Not Found"
        if name == "send_email":
            env.outbound.append({"channel": "email", "to": str(args["to"]),
                                 "content": f"{args.get('subject', '')}\n{args['body']}"})
            return f"Email sent to {args['to']}."
        if name == "http_post":
            env.outbound.append({"channel": "http", "to": str(args["url"]),
                                 "content": str(args["body"])})
            return "200 OK"
        if name == "delete_file":
            path = args["path"]
            if path not in env.files:
                return f"Error: file not found: {path}"
            del env.files[path]
            env.deleted.append(path)
            return f"Deleted {path}."
        return f"Error: unknown tool {name!r}"
    except (KeyError, TypeError) as exc:
        return f"Error: bad arguments for {name}: {exc}"
