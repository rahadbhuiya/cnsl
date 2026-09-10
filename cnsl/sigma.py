"""
cnsl/sigma.py -- Sigma detection rule import and matching.

Sigma (https://github.com/SigmaHQ/sigma) is the closest thing the
detection-engineering community has to a common rule format: YAML files
with named field-match "selections" and a small boolean condition
language ("selection1 and not selection2", "1 of selection_*", ...).
Thousands of community rules already exist; importing them gives CNSL
access to detection logic nobody here had to hand-write, and gives
teams already using Sigma elsewhere a way to bring their rules along.

Scope -- this implements a practical SUBSET of the Sigma spec, not the
full spec:

  Supported:
    - detection: named selections (map or list-of-maps == OR, plain
      list-of-strings == full-text/keyword search) + a condition string
    - Field modifiers: contains, startswith, endswith, re, all, cased
    - Condition operators: and, or, not, parentheses, "N of x*",
      "all of x*", "1 of them" / "all of them"
    - logsource, level, tags, falsepositives, references (carried
      through as metadata; logsource is not used to filter events --
      see note below)

  NOT supported (rejected at import time with a clear reason, not
  silently mis-evaluated):
    - Sigma "correlation" rules (the newer cross-event spec extension)
    - Aggregation functions (count() by, near, temporal) -- CNSL's own
      threshold/correlation engine (rules.py, correlator.py) already
      covers that; Sigma import here is for PER-EVENT field matching
    - Modifiers beyond the list above (base64, cidr, fieldref, expand)

Why logsource isn't used to filter: Sigma's logsource block (product,
service, category) assumes a taxonomy of Windows Event Log channels
and Sysmon event types that CNSL's Linux-focused normalized Event model
doesn't share. Rather than build (and inevitably get wrong) a mapping
from every logsource combination to CNSL's event kinds, this engine
just evaluates every enabled rule's detection logic against every
event's actual fields -- a rule whose fields never appear in any event
this instance sees simply never fires, which is the same practical
outcome as filtering by logsource, without the mapping to get wrong.

Field resolution, in order:
  1. A small alias table onto the Event's own typed attributes, so
     rules written for common field names (SourceIp, TargetUserName,
     User, src_ip, ...) resolve without every rule needing to match
     CNSL's exact field names. This also aliases CNSL's own `kind`
     and `source` fields, so a selection can match on event kind
     (e.g. `kind: SSH_FAIL`) the way a Sigma/Windows rule would match
     on EventID.
  2. ev.meta (case-insensitive key lookup) -- parsers already put
     structured per-source fields here (event_name, rule_id,
     agent_name, method, path, ...).
  3. ev.raw, as a last-resort substring search -- best-effort only,
     no modifier logic beyond plain containment, for rules whose
     field isn't captured anywhere else.

Because most public Sigma rules target Windows/Sysmon fields CNSL's
sources never produce, only a fraction of any given rule pack will
ever match live traffic here -- that's expected. The value is
interoperability, not "every rule fires."
"""

from __future__ import annotations

import fnmatch
import re as _re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None


_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}

_LEVEL_TO_SEVERITY = {
    "informational": "LOW",
    "low":           "LOW",
    "medium":        "MEDIUM",
    "high":          "HIGH",
    "critical":      "HIGH",
}

# Sigma field name -> attribute on cnsl.models.Event. Checked before
# falling back to ev.meta / ev.raw. Names are matched case-insensitively.
_FIELD_ALIASES = {
    "src_ip": "src_ip", "srcip": "src_ip", "sourceip": "src_ip",
    "source_ip": "src_ip", "ip": "src_ip", "clientip": "src_ip",
    "c-ip": "src_ip",
    "dst_ip": "dst_ip", "dstip": "dst_ip", "destinationip": "dst_ip",
    "destination_ip": "dst_ip",
    "user": "user", "username": "user", "targetusername": "user",
    "user_name": "user", "account": "user", "accountname": "user",
    "kind": "kind", "eventkind": "kind", "event_kind": "kind",
    "source": "source", "logsource_name": "source",
}


class SigmaImportError(Exception):
    """Raised when a Sigma rule file can't be imported (bad YAML, unsupported feature)."""


#  Field / selection matching


def _get_field(ev: Any, field_name: str) -> Any:
    """Resolve a Sigma field name against an Event -- see module docstring for order."""
    alias = _FIELD_ALIASES.get(field_name.lower())
    if alias is not None:
        return getattr(ev, alias, None)
    meta = getattr(ev, "meta", None) or {}
    for k, v in meta.items():
        if k.lower() == field_name.lower():
            return v
    return None


def _values_of(raw: Any) -> List[Any]:
    """Sigma field values may be a single scalar or a list -- always treat as a list (OR)."""
    if isinstance(raw, list):
        return raw
    return [raw]


def _match_one(field_value: Any, want: Any, modifiers: List[str]) -> bool:
    """Does field_value satisfy a single wanted value, under the given modifiers?"""
    if want is None:
        return field_value is None
    if field_value is None:
        return False

    fv = str(field_value)
    wv = str(want)
    if "cased" not in modifiers:
        fv_cmp, wv_cmp = fv.lower(), wv.lower()
    else:
        fv_cmp, wv_cmp = fv, wv

    if "re" in modifiers:
        try:
            return bool(_re.search(want, fv))
        except _re.error:
            return False
    if "contains" in modifiers:
        return wv_cmp in fv_cmp
    if "startswith" in modifiers:
        return fv_cmp.startswith(wv_cmp)
    if "endswith" in modifiers:
        return fv_cmp.endswith(wv_cmp)
    return fv_cmp == wv_cmp


def _match_field_spec(ev: Any, raw_field: str, want: Any) -> bool:
    """
    Evaluate one "field[|modifiers]: value" entry from a selection map
    against an event. `want` may be a scalar or a list (OR'd together,
    unless the "all" modifier is present, in which case every value in
    the list must match -- e.g. field|contains|all: [a, b]).
    """
    parts = raw_field.split("|")
    field_name, modifiers = parts[0], parts[1:]

    unknown = set(modifiers) - _SUPPORTED_MODIFIERS
    if unknown:
        # Import-time validation should already have caught this --
        # fail closed (never match) rather than mis-evaluate silently.
        return False

    field_value = _get_field(ev, field_name)

    if want is None:
        return field_value is None

    if field_value is None:
        # Fall back to a substring search over the raw log line -- the
        # only thing we can still do without a modifier-aware match.
        raw_text = getattr(ev, "raw", None) or ""
        wants = _values_of(want)
        if "all" in modifiers:
            return all(str(w).lower() in raw_text.lower() for w in wants)
        return any(str(w).lower() in raw_text.lower() for w in wants)

    wants = _values_of(want)
    if "all" in modifiers:
        return all(_match_one(field_value, w, modifiers) for w in wants)
    return any(_match_one(field_value, w, modifiers) for w in wants)


def _match_selection_map(ev: Any, sel: Dict[str, Any]) -> bool:
    """A selection map is an AND of all its field:value entries."""
    return all(_match_field_spec(ev, k, v) for k, v in sel.items())


def _match_selection(ev: Any, sel: Any) -> bool:
    """
    A selection can be:
      - a dict            -> AND of its fields
      - a list of dicts   -> OR across the list (each item AND'd internally)
      - a list of scalars -> keyword search: raw log line contains any of them
    """
    if isinstance(sel, dict):
        return _match_selection_map(ev, sel)
    if isinstance(sel, list):
        if not sel:
            return False
        if all(isinstance(item, dict) for item in sel):
            return any(_match_selection_map(ev, item) for item in sel)
        # Keyword list -- plain substring search against the raw line
        raw_text = (getattr(ev, "raw", None) or "").lower()
        return any(str(item).lower() in raw_text for item in sel)
    return False


#  Condition mini-language


_TOKEN_RE = _re.compile(r"\(|\)|[A-Za-z0-9_.*]+")


def _tokenize(condition: str) -> List[str]:
    return _TOKEN_RE.findall(condition)


class _ConditionParser:
    """
    Recursive-descent parser/evaluator for Sigma's condition string.

    Grammar (case-insensitive keywords):
        or_expr   := and_expr ("or" and_expr)*
        and_expr  := not_expr ("and" not_expr)*
        not_expr  := "not" not_expr | atom
        atom      := "(" or_expr ")"
                   | NUMBER "of" SELECTOR
                   | "all" "of" SELECTOR
                   | IDENTIFIER
        SELECTOR  := IDENTIFIER (may contain '*' wildcards) | "them"
    """

    def __init__(self, tokens: List[str], selection_names: List[str]):
        self._toks = tokens
        self._pos  = 0
        self._names = selection_names

    def _peek(self) -> Optional[str]:
        return self._toks[self._pos] if self._pos < len(self._toks) else None

    def _next(self) -> str:
        t = self._toks[self._pos]
        self._pos += 1
        return t

    def parse(self) -> "_Node":
        node = self._or_expr()
        if self._pos != len(self._toks):
            raise SigmaImportError(f"unexpected token '{self._peek()}' in condition")
        return node

    def _or_expr(self) -> "_Node":
        left = self._and_expr()
        while self._peek() and self._peek().lower() == "or":
            self._next()
            right = self._and_expr()
            left = _Node("or", left, right)
        return left

    def _and_expr(self) -> "_Node":
        left = self._not_expr()
        while self._peek() and self._peek().lower() == "and":
            self._next()
            right = self._not_expr()
            left = _Node("and", left, right)
        return left

    def _not_expr(self) -> "_Node":
        if self._peek() and self._peek().lower() == "not":
            self._next()
            return _Node("not", self._not_expr())
        return self._atom()

    def _atom(self) -> "_Node":
        tok = self._peek()
        if tok is None:
            raise SigmaImportError("unexpected end of condition")

        if tok == "(":
            self._next()
            inner = self._or_expr()
            if self._peek() != ")":
                raise SigmaImportError("missing closing ')' in condition")
            self._next()
            return inner

        low = tok.lower()
        if low == "all" and self._pos + 1 < len(self._toks) and self._toks[self._pos + 1].lower() == "of":
            self._next(); self._next()  # consume "all" "of"
            selector = self._next()
            return _Node("all_of", selector)

        if tok.isdigit() and self._pos + 1 < len(self._toks) and self._toks[self._pos + 1].lower() == "of":
            n = int(self._next()); self._next()  # consume NUMBER "of"
            selector = self._next()
            return _Node("n_of", selector, n=n)

        # Plain selection reference
        self._next()
        return _Node("ref", tok)


def _collect_refs(node: "_Node", out: List[str]) -> None:
    """Walk a condition tree, collecting every literal ('ref') selection name."""
    if node.kind == "ref":
        out.append(node.a)
    elif node.kind == "not":
        _collect_refs(node.a, out)
    elif node.kind in ("and", "or"):
        _collect_refs(node.a, out)
        _collect_refs(node.b, out)
    # "n_of" / "all_of" selectors are wildcard patterns (or "them"),
    # not literal selection names -- nothing to validate against
    # selections.keys() here; matching zero of them is valid.


@dataclass
class _Node:
    kind: str
    a: Any = None
    b: Any = None
    n: Optional[int] = None

    def eval(self, results: Dict[str, bool]) -> bool:
        if self.kind == "ref":
            if self.a not in results:
                raise SigmaImportError(f"condition references unknown selection '{self.a}'")
            return results[self.a]
        if self.kind == "and":
            return self.a.eval(results) and self.b.eval(results)
        if self.kind == "or":
            return self.a.eval(results) or self.b.eval(results)
        if self.kind == "not":
            return not self.a.eval(results)
        if self.kind in ("n_of", "all_of"):
            selector = self.a
            if selector.lower() == "them":
                matched = list(results.values())
            else:
                pattern = selector
                matched = [v for k, v in results.items() if fnmatch.fnmatch(k, pattern)]
            if not matched:
                return False
            if self.kind == "all_of":
                return all(matched)
            return sum(1 for m in matched if m) >= (self.n or 1)
        raise SigmaImportError(f"unknown condition node kind '{self.kind}'")


#  Compiled rule


@dataclass
class SigmaRule:
    """A single imported and compiled Sigma rule."""

    id:            str
    title:         str
    description:   str
    severity:      str                 # mapped LOW/MEDIUM/HIGH
    level:         str                 # original Sigma level string
    tags:          List[str]
    logsource:     Dict[str, str]
    falsepositives: List[str]
    references:    List[str]
    source_path:   str
    enabled:       bool = True

    _selection_names: List[str] = field(default_factory=list, repr=False)
    _selections:       Dict[str, Any] = field(default_factory=dict, repr=False)
    _condition_node:   Any = field(default=None, repr=False)

    def matches(self, ev: Any) -> bool:
        if not self.enabled:
            return False
        results = {name: _match_selection(ev, sel) for name, sel in self._selections.items()}
        try:
            return self._condition_node.eval(results)
        except SigmaImportError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "level": self.level, "tags": self.tags,
            "logsource": self.logsource, "falsepositives": self.falsepositives,
            "references": self.references, "source_path": self.source_path,
            "enabled": self.enabled,
        }


def compile_rule(doc: Dict[str, Any], source_path: str = "") -> SigmaRule:
    """
    Compile one parsed Sigma YAML document into a SigmaRule.
    Raises SigmaImportError with a specific reason on anything unsupported.
    """
    if not isinstance(doc, dict):
        raise SigmaImportError("rule document is not a YAML mapping")

    if "correlation" in doc:
        raise SigmaImportError("Sigma correlation rules are not supported -- use CNSL's own correlator.py for cross-event logic")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaImportError("missing or invalid 'detection' block")

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        raise SigmaImportError("missing 'condition' string in detection block")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaImportError("detection block has no selections")

    for name, sel in selections.items():
        for spec in _iter_field_specs(sel):
            mods = spec.split("|")[1:]
            unknown = set(mods) - _SUPPORTED_MODIFIERS
            if unknown:
                raise SigmaImportError(
                    f"selection '{name}' uses unsupported modifier(s) {sorted(unknown)} "
                    f"on field '{spec}'"
                )

    tokens = _tokenize(condition)
    if not tokens:
        raise SigmaImportError("empty condition")
    node = _ConditionParser(tokens, list(selections.keys())).parse()

    # Validate every literal selection reference exists -- walked
    # explicitly rather than caught via a dry-run eval(), because
    # Python's and/or short-circuit and would otherwise skip
    # evaluating (and thus validating) the right-hand side of an
    # "and" whenever the left side is False. Wildcard selectors used
    # by "N of x*" / "all of x*" are patterns, not literal names, so
    # they're intentionally not checked here -- matching zero
    # selections is valid (the condition just evaluates to False).
    refs: List[str] = []
    _collect_refs(node, refs)
    unknown_refs = sorted(set(refs) - set(selections.keys()))
    if unknown_refs:
        raise SigmaImportError(
            f"condition references unknown selection(s): {unknown_refs}"
        )

    level = str(doc.get("level", "medium")).lower()
    severity = _LEVEL_TO_SEVERITY.get(level, "MEDIUM")

    rule = SigmaRule(
        id             = str(doc.get("id") or doc.get("title") or Path(source_path).stem),
        title          = str(doc.get("title", "Untitled Sigma rule")),
        description    = str(doc.get("description", "")),
        severity       = severity,
        level          = level,
        tags           = list(doc.get("tags", []) or []),
        logsource      = dict(doc.get("logsource", {}) or {}),
        falsepositives = list(doc.get("falsepositives", []) or []),
        references     = list(doc.get("references", []) or []),
        source_path    = source_path,
    )
    rule._selection_names = list(selections.keys())
    rule._selections       = selections
    rule._condition_node   = node
    return rule


def _iter_field_specs(sel: Any):
    """Yield every 'field|modifiers' key in a selection, however it's nested."""
    if isinstance(sel, dict):
        yield from sel.keys()
    elif isinstance(sel, list):
        for item in sel:
            if isinstance(item, dict):
                yield from item.keys()


#  Rule store -- import, list, enable/disable


class SigmaRuleStore:
    """
    Holds all imported Sigma rules and evaluates them against events.

    Import failures are collected, not raised -- one malformed rule
    in a pack of 500 shouldn't block the other 499. Call import_dir()
    or import_file() at startup, then check import_errors() to surface
    what didn't make it in (dashboard / CLI output).
    """

    def __init__(self) -> None:
        self._rules: Dict[str, SigmaRule] = {}
        self._errors: List[Dict[str, str]] = []

    def import_file(self, path: str) -> Optional[SigmaRule]:
        if yaml is None:
            self._errors.append({"path": path, "error": "PyYAML not installed -- pip install PyYAML"})
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            self._errors.append({"path": path, "error": f"YAML parse error: {e}"})
            return None

        # Sigma files are occasionally multi-document (rule + shared
        # anchors) -- take the first mapping that has a 'detection' key.
        doc = next((d for d in docs if isinstance(d, dict) and "detection" in d), None)
        if doc is None:
            self._errors.append({"path": path, "error": "no rule document with a 'detection' block found"})
            return None

        try:
            rule = compile_rule(doc, source_path=path)
        except SigmaImportError as e:
            self._errors.append({"path": path, "error": str(e)})
            return None

        self._rules[rule.id] = rule
        return rule

    def import_dir(self, directory: str) -> Dict[str, int]:
        d = Path(directory)
        if not d.is_dir():
            self._errors.append({"path": directory, "error": "not a directory"})
            return {"imported": 0, "failed": 0}
        imported = 0
        failed   = 0
        for path in sorted(d.rglob("*.yml")) + sorted(d.rglob("*.yaml")):
            if self.import_file(str(path)) is not None:
                imported += 1
            else:
                failed += 1
        return {"imported": imported, "failed": failed}

    def import_text(self, yaml_text: str, label: str = "<inline>") -> Optional[SigmaRule]:
        """Import a single rule from an in-memory YAML string (e.g. dashboard upload)."""
        if yaml is None:
            self._errors.append({"path": label, "error": "PyYAML not installed -- pip install PyYAML"})
            return None
        try:
            doc = yaml.safe_load(yaml_text)
        except Exception as e:
            self._errors.append({"path": label, "error": f"YAML parse error: {e}"})
            return None
        try:
            rule = compile_rule(doc, source_path=label)
        except SigmaImportError as e:
            self._errors.append({"path": label, "error": str(e)})
            return None
        self._rules[rule.id] = rule
        return rule

    def import_errors(self) -> List[Dict[str, str]]:
        return list(self._errors)

    def clear_errors(self) -> None:
        self._errors.clear()

    def get(self, rule_id: str) -> Optional[SigmaRule]:
        return self._rules.get(rule_id)

    def enable(self, rule_id: str) -> Optional[str]:
        r = self._rules.get(rule_id)
        if not r:
            return f"Unknown Sigma rule '{rule_id}'."
        r.enabled = True
        return None

    def disable(self, rule_id: str) -> Optional[str]:
        r = self._rules.get(rule_id)
        if not r:
            return f"Unknown Sigma rule '{rule_id}'."
        r.enabled = False
        return None

    def all_rules(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in sorted(self._rules.values(), key=lambda r: r.id)]

    def __len__(self) -> int:
        return len(self._rules)

    def evaluate(self, ev: Any) -> List[SigmaRule]:
        """Return every enabled rule that matches this event."""
        return [r for r in self._rules.values() if r.matches(ev)]