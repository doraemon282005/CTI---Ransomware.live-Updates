from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    api_key: str
    base_url: str
    keywords: tuple[str, ...]
    output_dir: Path
    state_db: Path
    onion_proxy: str | None


def load_settings() -> Settings:
    load_dotenv()
    api_key = os.getenv("RANSOMWARE_LIVE_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "RANSOMWARE_LIVE_API_KEY is missing. Copy .env.example to .env and paste the key."
        )
    keywords = tuple(
        item.strip().casefold()
        for item in os.getenv(
            "TELECOM_KEYWORDS",
            "telecom,telecommunication,telecommunications,telecom sector,telecom industry",
        ).split(",")
        if item.strip()
    )
    return Settings(
        api_key=api_key,
        base_url=os.getenv("RANSOMWARE_LIVE_BASE_URL", "https://api-pro.ransomware.live").rstrip("/"),
        keywords=keywords,
        output_dir=Path("reports"),
        state_db=Path(".ransomware_state.sqlite3"),
        onion_proxy=os.getenv("ONION_PROXY", "").strip() or None,
    )
