#= capture.py  version 0.1.0 (2026-11-09)
#= Keeps only the eslogger events that belong to a scripted capture (those mentioning given markers, e.g. the scratch folder)
#= and replaces your home folder path, so the resulting file is small and safe to share. Used by scripts/capture-file-events.sh.
from __future__ import annotations

import json
from typing import Dict, Iterable, List, Sequence, Tuple


def filter_capture(lines: Iterable[str], markers: Sequence[str], home: str = "", replacement: str = "/Users/me") -> Tuple[List[str], Dict[str, int]]:
    """Returns (kept lines as compact JSON, count per eslogger event name). Lines that are not JSON events are dropped."""
    kept: List[str] = []
    counts: Dict[str, int] = {}
    wanted = [m for m in markers if m]
    for raw in lines:
        text = raw.strip()
        if not text.startswith("{"):
            continue
        try:
            obj = json.loads(text)
        except ValueError:
            continue
        body = obj.get("event") if isinstance(obj, dict) else None
        if not isinstance(body, dict) or not body:
            continue
        haystack = json.dumps(body, ensure_ascii=False)            #= after parsing, "\/" is a plain "/" again
        if wanted and not any(m in haystack for m in wanted):
            continue
        out = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        if home and home != "/":
            out = out.replace(home, replacement)
        kept.append(out)
        name = next(iter(body))
        counts[name] = counts.get(name, 0) + 1
    return kept, counts
