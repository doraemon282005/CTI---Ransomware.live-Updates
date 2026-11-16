from __future__ import annotations

import tkinter as tk
import webbrowser

from .monitor import Event, display_date, event_summary, has_value, intelligence_fields


INK = "#18353A"
MUTED = "#64777A"
PAPER = "#F1F5F4"
ACCENT = "#087E75"
GREEN = "#16724A"
MISSING = "#9AA8A8"


def _open_source(event: tk.Event, url: str) -> None:
    event.widget.configure(cursor="hand2")
    webbrowser.open(url)


def _add_incident(parent: tk.Widget, event: Event) -> None:
    card = tk.Frame(parent, bg="white", padx=20, pady=18, highlightthickness=1, highlightbackground="#D8E3E1")
    card.pack(fill="x", padx=22, pady=(0, 14))
    heading = tk.Frame(card, bg="white")
    heading.pack(fill="x")
    tk.Label(
        heading,
        text=event.organization,
        bg="white",
        fg=INK,
        font=("Segoe UI Semibold", 17),
        anchor="w",
    ).pack(side="left", fill="x", expand=True)
    tk.Label(
        heading,
        text=f"THREAT ACTOR  {event.group_name}",
        bg="#E4F2EF",
        fg=ACCENT,
        font=("Segoe UI Semibold", 9),
        padx=10,
        pady=6,
    ).pack(side="right", padx=(12, 0))

    tk.Label(
        card,
        text="INCIDENT SUMMARY",
        bg="white",
        fg=MUTED,
        font=("Segoe UI Semibold", 9),
        anchor="w",
    ).pack(fill="x", pady=(16, 5))
    summary = " ".join(event_summary(event)) or "Not available in ransomware.live data"
    summary_label = tk.Label(
        card,
        text=summary,
        bg="white",
        fg=INK,
        font=("Segoe UI", 10),
        justify="left",
        anchor="w",
        wraplength=820,
    )
    summary_label.pack(fill="x")
    card.bind(
        "<Configure>",
        lambda layout_event: summary_label.configure(wraplength=max(320, min(820, layout_event.width - 48))),
    )

    dates = tk.Frame(card, bg="#F5F8F7", padx=12, pady=10)
    dates.pack(fill="x", pady=(14, 14))
    dates.grid_columnconfigure((0, 1), weight=1)
    for column, (label, value) in enumerate((
        ("DISCOVERED", display_date(event.discovered)),
        ("ATTACK DATE", display_date(event.victim.get("attackdate") or event.source.get("attackdate"))),
    )):
        item = tk.Frame(dates, bg="#F5F8F7")
        item.grid(row=0, column=column, sticky="ew", padx=(0, 12) if column == 0 else (12, 0))
        tk.Label(item, text=label, bg="#F5F8F7", fg=MUTED, font=("Segoe UI Semibold", 8), anchor="w").pack(fill="x")
        tk.Label(item, text=value, bg="#F5F8F7", fg=INK, font=("Segoe UI", 10), anchor="w").pack(fill="x", pady=(3, 0))

    tk.Label(
        card,
        text="THREAT ACTOR INTELLIGENCE",
        bg="white",
        fg=MUTED,
        font=("Segoe UI Semibold", 9),
        anchor="w",
    ).pack(fill="x", pady=(0, 8))
    checks = tk.Frame(card, bg="white")
    checks.pack(fill="x")
    checks.grid_columnconfigure(tuple(range(5)), weight=1)
    for field_index, (label, value) in enumerate(intelligence_fields(event)):
        present = has_value(value)
        marker = tk.Label(
            checks,
            text=f"{chr(10003) if present else chr(8212)}  {label}",
            bg="white",
            fg=GREEN if present else MISSING,
            font=("Segoe UI", 9),
            anchor="w",
        )
        marker.grid(row=field_index // 5, column=field_index % 5, sticky="w", padx=(0, 6), pady=5)

    source_url = event.article_url
    source = tk.Label(
        card,
        text=f"OPEN SOURCE ARTICLE  {chr(8599)}" if source_url.startswith(("http://", "https://")) else "SOURCE ARTICLE UNAVAILABLE",
        bg="white",
        fg=ACCENT if source_url.startswith(("http://", "https://")) else MISSING,
        font=("Segoe UI Semibold", 9),
        anchor="w",
        cursor="hand2" if source_url.startswith(("http://", "https://")) else "",
    )
    source.pack(anchor="w", pady=(13, 0))
    if source_url.startswith(("http://", "https://")):
        source.bind("<Button-1>", lambda click, url=source_url: _open_source(click, url))


def show_popup(events: list[Event]) -> None:
    window = tk.Tk()
    window.title("Ransomware.live | Telecom CTI")
    window.geometry("920x760")
    window.minsize(760, 560)
    window.configure(bg=PAPER)

    header = tk.Frame(window, bg=INK, padx=24, pady=17)
    header.pack(fill="x")
    tk.Label(
        header,
        text="RANSOMWARE.LIVE  /  TELECOM CTI",
        bg=INK,
        fg="#A8D9CC",
        font=("Segoe UI Semibold", 9),
        anchor="w",
    ).pack(fill="x")
    header_row = tk.Frame(header, bg=INK)
    header_row.pack(fill="x", pady=(5, 0))
    tk.Label(
        header_row,
        text="Industry incident monitor",
        bg=INK,
        fg="white",
        font=("Segoe UI Semibold", 19),
        anchor="w",
    ).pack(side="left", fill="x", expand=True)
    count_text = f"{len(events)} NEW INCIDENT{'S' if len(events) != 1 else ''}"
    tk.Label(
        header_row,
        text=count_text,
        bg="#087E75",
        fg="white",
        font=("Segoe UI Semibold", 9),
        padx=11,
        pady=7,
    ).pack(side="right")

    content = tk.Frame(window, bg=PAPER)
    content.pack(fill="both", expand=True)
    canvas = tk.Canvas(content, bg=PAPER, highlightthickness=0, bd=0)
    scrollbar = tk.Scrollbar(content, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    list_frame = tk.Frame(canvas, bg=PAPER, padx=0, pady=20)
    frame_id = canvas.create_window((0, 0), window=list_frame, anchor="nw")
    list_frame.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(frame_id, width=event.width))
    canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(int(-event.delta / 120), "units"))

    if events:
        for event in events:
            _add_incident(list_frame, event)
    else:
        empty = tk.Frame(list_frame, bg="white", padx=28, pady=30, highlightthickness=1, highlightbackground="#D8E3E1")
        empty.pack(fill="x", padx=22, pady=20)
        tk.Label(empty, text="No relevant updates.", bg="white", fg=INK, font=("Segoe UI Semibold", 16), anchor="w").pack(fill="x")

    footer = tk.Frame(window, bg="white", padx=20, pady=10, highlightthickness=1, highlightbackground="#D8E3E1")
    footer.pack(fill="x", side="bottom")
    tk.Label(footer, text="Source: ransomware.live", bg="white", fg=MUTED, font=("Segoe UI", 9)).pack(side="left")
    tk.Button(
        footer,
        text="Close",
        command=window.destroy,
        bg=INK,
        fg="white",
        activebackground="#294B50",
        activeforeground="white",
        relief="flat",
        padx=18,
        pady=7,
        font=("Segoe UI Semibold", 9),
        cursor="hand2",
    ).pack(side="right")
    window.mainloop()
