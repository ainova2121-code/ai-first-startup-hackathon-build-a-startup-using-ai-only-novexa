"""n8n's public REST API (``/api/v1``), only the calls the platform needs: read and update workflows, create and
delete the credentials a fix moves a secret into, and read executions. The API key comes from the operator
(``N8N_API_KEY``), travels only in its header, and is never logged or returned.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

# What n8n's PUT /workflows/{id} accepts; anything else in a fetched workflow (id, active, tags...) is refused by it.
_WRITABLE = ("name", "nodes", "connections", "settings", "staticData")
_SETTINGS = {"saveExecutionProgress", "saveManualExecutions", "saveDataErrorExecution", "saveDataSuccessExecution",
             "executionTimeout", "errorWorkflow", "timezone", "executionOrder", "callerPolicy", "callerIds"}


class N8nError(RuntimeError):
    """n8n refused or could not be reached; carries the status and n8n's own message, never the key."""


class N8nClient:
    def __init__(self, base_url: str, api_key: SecretStr | str, *, timeout: float = 30,
                 transport: httpx.BaseTransport | None = None) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.username or parts.password:
            raise ValueError("the n8n URL must be a plain http(s) URL")
        key = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(base_url=f"{self.base_url}/api/v1", timeout=timeout, transport=transport,
                                  follow_redirects=False, headers={"X-N8N-API-KEY": key, "Accept": "application/json"})

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.HTTPError as error:
            raise N8nError(f"could not reach n8n ({type(error).__name__})") from error
        if response.status_code >= 400:
            try:
                message = response.json().get("message", "")
            except ValueError:
                message = ""
            raise N8nError(f"n8n answered {response.status_code} to {method} {path}: {str(message)[:200]}")
        return response.json() if response.content else None

    def workflow(self, workflow_id: str) -> dict:
        return self._call("GET", f"/workflows/{_safe_id(workflow_id)}")

    def update_workflow(self, workflow_id: str, workflow: dict) -> dict:
        body = {key: workflow[key] for key in _WRITABLE if key in workflow}
        body["settings"] = {k: v for k, v in (workflow.get("settings") or {}).items() if k in _SETTINGS}
        return self._call("PUT", f"/workflows/{_safe_id(workflow_id)}", json=body)

    def create_credential(self, name: str, kind: str, data: dict) -> dict:
        return self._call("POST", "/credentials", json={"name": name, "type": kind, "data": data})

    def delete_credential(self, credential_id: str) -> None:
        self._call("DELETE", f"/credentials/{_safe_id(credential_id)}")

    def executions(self, workflow_id: str, limit: int = 20) -> list[dict]:
        """The newest executions of one workflow, with the data every node produced."""
        body = self._call("GET", "/executions", params={"workflowId": _safe_id(workflow_id), "includeData": "true",
                                                        "limit": min(max(limit, 1), 250)})
        return body.get("data", []) if isinstance(body, dict) else []


def _safe_id(value: str) -> str:
    """n8n ids are short alphanumeric strings; anything else is refused before it can shape a URL path."""
    if not (isinstance(value, str) and value.isalnum() and len(value) <= 64):
        raise ValueError("an n8n id is 1-64 letters or digits")
    return value
