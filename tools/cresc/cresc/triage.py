#= triage.py  version 0.1.0 (2026-11-07)
#= Combines parsing, classification, risk and rule synthesis into one reviewable list.
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .classify import classify, risk
from .denials import Group
from .rules import Rule, prefix_suggestions, synthesize


@dataclass
class Item:
    group: Group
    klass: str                 #= benign | path-search | candidate
    reason: str
    risk: str                  #= low | medium | high
    rule: Optional[Rule]

    @property
    def needs_confirm(self) -> bool:
        return self.risk == "high" or (self.rule is not None and self.rule.confirm)

    def to_dict(self) -> Dict:
        d = self.group.to_dict()
        d.update({"class": self.klass, "reason": self.reason, "risk": self.risk,
                  "needs_confirm": self.needs_confirm, "rule": self.rule.to_dict() if self.rule else None})
        return d


def triage(groups: Sequence[Group], entries: Sequence[str] = (), home: str = "") -> List[Item]:
    items: List[Item] = []
    for g in groups:
        klass, reason = classify(g, entries, home)
        rule = synthesize(g) if klass == "candidate" else None
        items.append(Item(group=g, klass=klass, reason=reason, risk=risk(g.op, g.target, home), rule=rule))
    return items


def summary(items: Sequence[Item]) -> Dict:
    out = {"groups": len(items), "benign": 0, "path-search": 0, "candidate": 0,
           "candidate_with_rule": 0, "low": 0, "medium": 0, "high": 0}
    for it in items:
        out[it.klass] += 1
        if it.klass == "candidate":
            out[it.risk] += 1
            if it.rule is not None:
                out["candidate_with_rule"] += 1
    return out


def suggested_prefixes(items: Sequence[Item]) -> List[Rule]:
    return prefix_suggestions([it.rule for it in items if it.rule is not None])
