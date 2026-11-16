from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any
from urllib.parse import quote, urlparse

import requests

from .api import RansomwareLiveClient
from .config import Settings
from .store import is_processed


MISSING = "Not available in ransomware.live data"


def text(value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return MISSING
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)
    return str(value)


def has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value != MISSING
    if isinstance(value, dict):
        return any(has_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(has_value(item) for item in value)
    return True


def summary_points(value: Any) -> list[str]:
    if not has_value(value):
        return []
    raw = text(value).strip()
    candidates = re.split(r"(?<=[.!?])\s+|\r?\n+", raw)
    points: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        point = " ".join(candidate.split()).strip(" -\t")
        key = re.sub(r"\W+", " ", point.casefold()).strip()
        if point and key not in seen:
            points.append(point)
            seen.add(key)
    return points


def _walk_tox(value: Any) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() == "tox":
                if has_value(item):
                    found.append(item)
            else:
                found.extend(_walk_tox(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_tox(item))
    return found


def tox_values(value: Any) -> list[Any]:
    unique: list[Any] = []
    seen: set[str] = set()
    for item in _walk_tox(value):
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique


def _without_tox(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: cleaned
            for key, item in value.items()
            if str(key).casefold() != "tox"
            and has_value(cleaned := _without_tox(item))
        }
    if isinstance(value, list):
        return [cleaned for item in value if has_value(cleaned := _without_tox(item))]
    return value


def ioc_values(value: Any) -> Any:
    if isinstance(value, dict) and "iocs" in value:
        value = value["iocs"]
    cleaned = _without_tox(value)
    return cleaned if has_value(cleaned) else None


def display_date(value: Any) -> str:
    if not has_value(value):
        return MISSING
    raw = str(value)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return raw


def parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raw = str(value).strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def in_recent_window(value: Any, window_hours: float | None, now: datetime | None = None) -> bool:
    if window_hours is None or window_hours <= 0:
        return True
    timestamp = parse_datetime(value)
    if timestamp is None:
        return True
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(hours=window_hours)
    return timestamp >= cutoff


def keyword_match(record: dict[str, Any], keywords: tuple[str, ...]) -> bool:
    fields = ("activity", "sector", "victim", "name", "website", "group", "group_name")
    haystack = " ".join(text(record.get(key)) for key in fields).casefold()
    return any(keyword in haystack for keyword in keywords)


def working_links(values: Any, proxy: str | None) -> list[str]:
    candidates: list[str] = []
    if isinstance(values, str):
        candidates = [values]
    elif isinstance(values, list):
        candidates = [str(item) for item in values]
    elif isinstance(values, dict):
        candidates = [str(value) for value in values.values()]
    result: list[str] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    for candidate in candidates:
        if not candidate.startswith(("http://", "https://")):
            continue
        parsed = urlparse(candidate)
        if parsed.hostname and parsed.hostname.endswith(".onion") and not proxy:
            continue
        try:
            response = requests.head(candidate, timeout=12, allow_redirects=True, proxies=proxies)
            if response.status_code < 400:
                result.append(candidate)
        except requests.RequestException:
            continue
    return list(dict.fromkeys(result))


@dataclass
class Event:
    event_id: str
    source: dict[str, Any]
    victim: dict[str, Any]
    group: dict[str, Any]
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def discovered(self) -> str:
        return text(self.victim.get("discovered") or self.source.get("discovered"))

    @property
    def group_name(self) -> str:
        return text(self.victim.get("group") or self.victim.get("group_name") or self.source.get("group"))

    @property
    def organization(self) -> str:
        return text(self.victim.get("victim") or self.source.get("victim") or self.victim.get("name"))

    @property
    def article_url(self) -> str:
        return text(self.victim.get("permalink") or self.source.get("permalink"))


def event_summary(event: Event) -> list[str]:
    # The API's `description` is often a victim-business profile (and can be
    # AI-generated), so it must not be presented as an account of the attack.
    # Only use fields whose names explicitly indicate incident/claim content.
    narrative_keys = {
        "incident_summary", "attack_summary", "incident_details", "attack_details",
        "claim_summary", "claim_details", "post_content", "leak_post_description",
    }
    narrative: Any = None
    for record in (event.victim, event.source):
        for key, value in record.items():
            if str(key).casefold() in narrative_keys and has_value(value):
                candidate = " ".join(text(value).split())
                if not re.search(r"\bAI[- ]generated\b", candidate, re.IGNORECASE):
                    narrative = candidate
                    break
        if narrative:
            break

    if narrative:
        points = summary_points(narrative)
        if points:
            return ["Claim details from ransomware.live: " + point for point in points[:2]]

    organization = event.organization
    group = event.group_name
    if organization == MISSING:
        claim = "ransomware.live lists a ransomware victim claim."
    elif group == MISSING:
        claim = f"Claim: {organization} is listed as a ransomware victim on ransomware.live."
    else:
        claim = f"Claim: {group} lists {organization} as a ransomware victim on ransomware.live."

    dates = []
    if event.discovered != MISSING:
        dates.append(f"listing discovered {display_date(event.discovered)}")
    attack_date = display_date(
        event.victim.get("attackdate")
        or event.source.get("attackdate")
        or event.victim.get("published")
        or event.source.get("published")
    )
    if attack_date != MISSING:
        dates.append(f"group-reported attack date {attack_date}")
    if dates:
        claim += " Recorded dates: " + "; ".join(dates) + "."

    limitation = "The source provides no incident narrative about access method, affected data or systems, or operational impact."
    return [claim, limitation]


def intelligence_fields(event: Event) -> list[tuple[str, Any]]:
    group = event.group
    victim = event.victim
    extras = event.extras
    ransom_notes = extras.get("ransom_notes")
    if isinstance(ransom_notes, dict) and "ransomnotes" in ransom_notes:
        ransom_notes = ransom_notes["ransomnotes"]
    yara = extras.get("yara")
    if isinstance(yara, dict) and "rules" in yara:
        yara = yara["rules"]
    return [
        ("Known location", group.get("locations")),
        ("Target", victim.get("activity") or victim.get("sector") or event.source.get("activity")),
        ("Heatmap", victim.get("country") or event.source.get("country")),
        ("Ransom notes", ransom_notes),
        ("Tools used", group.get("tools")),
        ("Vulnerabilities", group.get("vulnerabilities")),
        ("TTP matrix", group.get("ttps")),
        ("KQL queries", group.get("kql") or group.get("kql_queries")),
        ("YARA rules", yara),
        ("IOCs", ioc_values(extras.get("iocs"))),
    ]


def collect(settings: Settings, include_processed: bool = False, window_hours: float | None = None) -> list[Event]:
    client = RansomwareLiveClient(settings.base_url, settings.api_key)
    recent = client.recent_victims()
    events: list[Event] = []
    now = datetime.now(timezone.utc)
    for source in recent:
        if not keyword_match(source, settings.keywords):
            continue
        event_id = text(source.get("id") or source.get("permalink"))
        if event_id == MISSING or (not include_processed and is_processed(settings.state_db, event_id)):
            continue
        victim = client.victim(event_id) if source.get("id") else source
        discovered = source.get("discovered") or victim.get("discovered") or source.get("published") or victim.get("published")
        if not in_recent_window(discovered, window_hours, now):
            continue
        group_name = text(victim.get("group") or victim.get("group_name") or source.get("group"))
        encoded_group = quote(group_name, safe="")
        group = {} if group_name == MISSING else (client.optional(f"/groups/{encoded_group}") or {})
        event = Event(event_id=event_id, source=source, victim=victim, group=group)
        event.extras = {
            "ransom_notes": client.optional(f"/ransomnotes/{encoded_group}") if group_name != MISSING else None,
            "negotiations": client.optional(f"/negotiations/{encoded_group}") if group_name != MISSING else None,
            "yara": client.optional(f"/yara/{encoded_group}") if group_name != MISSING else None,
            "iocs": client.optional(f"/iocs/{encoded_group}") if group_name != MISSING else None,
            "working_links": working_links(group.get("locations"), settings.onion_proxy),
        }
        events.append(event)
    return events
