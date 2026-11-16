from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import requests


class RansomwareLiveClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"X-API-KEY": api_key, "Accept": "application/json"})

    def get(self, path: str, **params: Any) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        for attempt in range(3):
            response = self.session.get(url, params=params or None, timeout=45)
            if response.status_code == 429 and attempt < 2:
                time.sleep(float(response.headers.get("Retry-After", "5")))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError(f"Unable to fetch {url}")

    def recent_victims(self) -> list[dict[str, Any]]:
        payload = self.get("/victims/recent")
        return payload if isinstance(payload, list) else payload.get("victims", [])

    def victim(self, victim_id: str) -> dict[str, Any]:
        payload = self.get(f"/victim/{quote(victim_id, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def group(self, group_name: str) -> dict[str, Any]:
        payload = self.get(f"/groups/{quote(group_name, safe='')}")
        return payload if isinstance(payload, dict) else {}

    def optional(self, path: str, **params: Any) -> Any:
        try:
            return self.get(path, **params)
        except requests.HTTPError as error:
            if error.response is not None and error.response.status_code == 404:
                return None
            raise
