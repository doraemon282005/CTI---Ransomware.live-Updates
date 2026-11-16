from __future__ import annotations

import argparse
import logging
import time

from ransomware_monitor.config import load_settings
from ransomware_monitor.monitor import collect
from ransomware_monitor.notify import show_popup
from ransomware_monitor.reports import append_excel, clear_event_reports
from ransomware_monitor.store import initialize, mark_processed


def run_once(window_hours: float = 6) -> int:
    settings = load_settings()
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    initialize(settings.state_db)
    # Each refresh should surface only events discovered in the active reporting
    # window. Older incidents remain in the workbook, but the popup/report set is
    # scoped to the last N hours so a six-hour run does not keep re-showing stale
    # incidents from previous cycles.
    events = collect(settings, include_processed=True, window_hours=window_hours)
    clear_event_reports(settings.output_dir, window_hours=window_hours)
    for event in events:
        append_excel(event, settings.output_dir)
        mark_processed(settings.state_db, event.event_id, event.discovered)
    show_popup(events)
    logging.info("Refreshed reports and popup for %d telecom incident(s) in the last %.1f hours.", len(events), window_hours)
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor ransomware.live for telecom-sector incidents.")
    parser.add_argument("--run-once", action="store_true", help="Fetch, report, and show a popup once.")
    parser.add_argument("--interval-hours", type=float, default=6, help="Daemon interval (default: 6 hours).")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.run_once:
        run_once(window_hours=args.interval_hours)
        return
    while True:
        try:
            run_once(window_hours=args.interval_hours)
        except Exception:
            logging.exception("Monitoring run failed; the daemon will retry at the next interval.")
        time.sleep(args.interval_hours * 3600)


if __name__ == "__main__":
    main()
