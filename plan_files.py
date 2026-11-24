"""File-based plan for long Operator jobs.

Shape borrowed from planning-with-files: three markdown files per job, on disk,
so a plan survives a crash, a systemd restart or a context reset.

    ~/.jarvis-tools/plans/<job_id>/
        task_plan.md   phases with checkboxes; the resume point
        findings.md    decisions and durable notes
        progress.md    append-only session log, bounded

The Operator injects a bounded summary every step and refuses `finish` once
while phases remain unchecked. Files are the only state: deleting the folder
is a clean reset.
"""
from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from atomic_io import atomic_write_bytes

ROOT = Path.home() / ".jarvis-tools" / "plans"
JOB_ID = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
PHASE = re.compile(r"^\s*[-*]\s*\[( |x|X)\]\s+(.+?)\s*$")
MAX_PHASE = 160
MAX_PLAN_BYTES = 32_000
MAX_FINDINGS_BYTES = 48_000
MAX_PROGRESS_LINES = 400


class PlanError(ValueError):
    """A rejected plan operation."""


def _one_line(text, limit):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:limit]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_stem(lower: str, prefixes: tuple[str, ...]) -> bool:
    return any(re.search(r'(?:\b|_)' + re.escape(p), lower) for p in prefixes)


def decompose_task(task: str) -> list[str]:
    """Break a task description into 3-6 clear, actionable checkpoints."""
    text = str(task or "").strip()
    if not text:
        return ["Analiza zadania", "Realizacja działań", "Weryfikacja wyników"]

    # 1. Check if user already provided numbered or bulleted items
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    items = []
    for line in lines:
        cleaned = re.sub(r'^(?:\d+[\.\)]|\-|\*)\s*', '', line).strip()
        if len(cleaned) > 5 and cleaned != line:
            items.append(cleaned[:MAX_PHASE])
    if len(items) >= 2:
        return items[:6]

    # 1b. Compound single-sentence pipeline ("Sprawdź w notatkach X, porównaj w sieci Y i zapisz Z")
    try:
        import router
        compound_steps = router.parse_compound_steps(text)
        if len(compound_steps) >= 2:
            return [step["step"][:MAX_PHASE] for step in compound_steps[:6]]
    except Exception:
        pass

    # 2. Heuristic decomposition based on task intent
    lower = text.lower()
    is_pl = bool(re.search(r'[ąćęłńóśźż]|kino|agenc|napraw|sprawd|zrób|przetestuj|kod', lower))

    if _has_stem(lower, ("kino", "windows", "linux", "repair", "napraw", "błędy", "problems")):
        if is_pl:
            return [
                "Zlokalizowanie aplikacji i analiza struktury",
                "Utworzenie kopii zapasowej i test stanu bazowego",
                "Wykrycie niekompatybilności Windows na Linuksie",
                "Wdrożenie poprawek (ścieżki, biblioteki, runtime)",
                "Uruchomienie i testy weryfikacyjne na Linuksie",
            ]
        return [
            "Locate application and inspect project structure",
            "Create baseline backup and verify initial state",
            "Detect Windows-specific assumptions and defects",
            "Apply Linux runtime and path compatibility fixes",
            "Verify launch and test end-to-end functionality",
        ]
    if _has_stem(lower, ("agent", "agenci", "hermes", "opencode", "claude", "antigravity")):
        if is_pl:
            return [
                "Sprawdzenie obecności binariów i wersji agentów",
                "Weryfikacja konfiguracji i dostępnych modeli",
                "Test piaskownicy bwrap i uprawnień wykonawczych",
                "Raport gotowości operacyjnej agentów",
            ]
        return [
            "Check agent binaries and CLI availability",
            "Inspect configurations and model options",
            "Verify bwrap sandbox and execution permissions",
            "Report operational readiness status",
        ]
    if _has_stem(lower, ("scan", "audit", "kod", "code", "repo", "ulepsz", "upgrade", "optymalizuj", "przebadaj", "zbadaj")):
        if is_pl:
            return [
                "Przegląd struktury repozytorium i statusu git",
                "Analiza jakości kodu, testów i lintera",
                "Identyfikacja wąskich gardeł i obszarów optymalizacji",
                "Przygotowanie konkretnych propozycji ulepszeń",
            ]
        return [
            "Review repository structure and git status",
            "Analyze code quality, tests, and linter reports",
            "Identify bottlenecks and upgrade candidates",
            "Deliver concrete improvement recommendations",
        ]
    if _has_stem(lower, ("stron", "website", "web", "html", "css", "aplikacj", "landing", "zbuduj", "stwórz", "stworz", "frontend", "backend")):
        if is_pl:
            return [
                "Analiza wymagań i zaprojektowanie architektury",
                "Stworzenie szkieletu projektu i struktury plików",
                "Implementacja logiki, interfejsu i komponentów",
                "Stylowanie i weryfikacja responsywności",
                "Weryfikacja działania i testy końcowe",
            ]
        return [
            "Analyze requirements and design architecture",
            "Create project layout and baseline files",
            "Implement core logic, interface and components",
            "Apply styling, assets and responsive checks",
            "Validate execution and verify end-to-end functionality",
        ]
    if _has_stem(lower, ("znajdź", "znajdz", "poszukaj", "wyszukaj", "research", "search", "informacj", "artykuł", "artykul")):
        if is_pl:
            return [
                "Określenie kryteriów i źródeł wyszukiwania",
                "Pozyskanie danych ze stron internetowych lub bazy",
                "Weryfikacja faktów, synteza i odfiltrowanie szumu",
                "Opracowanie czytelnego podsumowania i wniosków",
            ]
        return [
            "Define search criteria and target sources",
            "Collect information from web sources or data store",
            "Verify facts, synthesize data and filter noise",
            "Deliver clear structured summary and findings",
        ]
    if _has_stem(lower, ("uporządkuj", "uporzadkuj", "posprzątaj", "posprzataj", "foldery", "katalog", "pliki", "cleanup", "organize", "porządk")):
        if is_pl:
            return [
                "Skanowanie katalogów i inwentaryzacja plików",
                "Zdefiniowanie reguł segregacji i czyszczenia",
                "Bezpieczne uporządkowanie lub archiwizacja elementów",
                "Weryfikacja spójności struktury po zmianach",
            ]
        return [
            "Scan directory tree and inventory existing files",
            "Define categorization and cleanup rules",
            "Safely reorganize or archive files",
            "Verify directory structure and validate outcome",
        ]
    if is_pl:
        return [
            "Rozpoznanie kontekstu i analiza wymagań",
            "Wykonanie głównych kroków zadania",
            "Weryfikacja poprawności rezultatów",
            "Podsumowanie i raport końcowy",
        ]
    return [
        "Analyze requirements and inspect environment",
        "Execute primary task operations",
        "Verify results and validate outcomes",
        "Deliver final completion summary",
    ]


class PlanFiles:
    def __init__(self, job_id, root=None):
        job_id = str(job_id or "").strip()
        if not JOB_ID.match(job_id):
            raise PlanError("A plan needs a valid job id.")
        self.job_id = job_id
        self.root = Path(root) if root else Path(
            os.environ.get("JARVIS_PLAN_ROOT") or ROOT)
        self.dir = self.root / job_id

    # -- paths ---------------------------------------------------------
    def path(self, name):
        return self.dir / name

    def exists(self):
        return self.path("task_plan.md").is_file()

    def _write(self, name, text, cap):
        encoded = str(text).encode("utf-8")
        if len(encoded) > cap:
            encoded = encoded[:cap].decode("utf-8", "ignore").encode("utf-8")
        atomic_write_bytes(self.path(name), encoded, mode=0o600, dir_mode=0o700)

    # The agent thread and operator calls can mutate the same plan in parallel;
    # RLock serialises all read-modify-write paths (start, add_phase, check,
    # check_all, note, log) without deadlocking nested calls.
    APPEND_LOCK = threading.RLock()

    @staticmethod
    def _tail_bytes(text, cap):
        """Keep the newest bytes; drop a partial first line left by the cut."""
        data = str(text).encode("utf-8")
        if len(data) <= cap:
            return str(text)
        tail = data[-cap:].decode("utf-8", "ignore")
        newline = tail.find("\n")
        return tail[newline + 1:] if newline >= 0 else tail

    def _append(self, name, text, cap, keep_lines=None):
        with self.APPEND_LOCK:
            current = ""
            try:
                current = self.path(name).read_text(encoding="utf-8")
            except OSError:
                pass
            merged = (current.rstrip("\n") + "\n" + str(text).rstrip("\n") + "\n").lstrip("\n")
            if keep_lines:
                lines = merged.splitlines()[-keep_lines:]
                merged = "\n".join(lines) + "\n"
                # The byte cap must drop the oldest lines, not the newest:
                # _write truncates from the head, which froze progress.md on
                # stale entries once the retained window reached MAX_PLAN_BYTES.
                merged = self._tail_bytes(merged, cap)
            self._write(name, merged, cap)

    # -- lifecycle -----------------------------------------------------
    def start(self, task, phases=()):
        """Create the plan once; an existing plan is a resume, never overwritten."""
        with self.APPEND_LOCK:
            if not self.exists():
                if not phases and task:
                    phases = decompose_task(task)
                body = [f"# Plan — {_now()}", "", f"Task: {_one_line(task, 500)}", "", "## Phases"]
                for phase in phases or ():
                    text = _one_line(phase, MAX_PHASE)
                    if text:
                        body.append(f"- [ ] {text}")
                self._write("task_plan.md", "\n".join(body) + "\n", MAX_PLAN_BYTES)
                self._write("findings.md", f"# Findings — {_now()}\n", MAX_FINDINGS_BYTES)
                self._write("progress.md", f"# Progress — {_now()}\n", MAX_PLAN_BYTES)
            return self.status()

    def phases(self):
        try:
            text = self.path("task_plan.md").read_text(encoding="utf-8")
        except OSError:
            return []
        rows = []
        for line in text.splitlines():
            match = PHASE.match(line)
            if match:
                rows.append({"text": match.group(2)[:MAX_PHASE],
                             "done": match.group(1).lower() == "x"})
        return rows

    def status(self):
        phases = self.phases()
        done = sum(1 for phase in phases if phase["done"])
        return {"job_id": self.job_id, "phases": phases, "done": done,
                "total": len(phases), "complete": done == len(phases),
                "dir": str(self.dir)}

    def add_phase(self, text):
        text = _one_line(text, MAX_PHASE)
        if not text:
            raise PlanError("A phase needs text.")
        with self.APPEND_LOCK:
            if self.exists():
                self._append("task_plan.md", f"- [ ] {text}", MAX_PLAN_BYTES)
            else:
                self.start("", [text])
            return self.status()

    def check(self, index=None):
        try:
            index = int(index)
        except (TypeError, ValueError):
            raise PlanError("A phase index is required.") from None
        with self.APPEND_LOCK:
            phases = self.phases()
            if index < 0 or index >= len(phases):
                raise PlanError(f"No phase at index {index}.")
            try:
                text = self.path("task_plan.md").read_text(encoding="utf-8")
            except OSError:
                raise PlanError("The plan file is missing.") from None
            lines, seen = [], 0
            for line in text.splitlines():
                match = PHASE.match(line)
                if match:
                    if seen == index:
                        line = f"- [x] {match.group(2)}"
                    seen += 1
                lines.append(line)
            self._write("task_plan.md", "\n".join(lines) + "\n", MAX_PLAN_BYTES)
            return self.status()

    def check_all(self):
        """Mark every phase as complete."""
        with self.APPEND_LOCK:
            try:
                text = self.path("task_plan.md").read_text(encoding="utf-8")
            except OSError:
                return self.status()
            lines = []
            for line in text.splitlines():
                match = PHASE.match(line)
                if match:
                    line = f"- [x] {match.group(2)}"
                lines.append(line)
            self._write("task_plan.md", "\n".join(lines) + "\n", MAX_PLAN_BYTES)
            return self.status()

    def note(self, text):
        text = str(text or "").strip()
        if not text:
            raise PlanError("A finding needs text.")
        self._append("findings.md", f"\n## {_now()}\n{text[:4000]}", MAX_FINDINGS_BYTES)
        return {"job_id": self.job_id, "findings_bytes": self.path("findings.md").stat().st_size}

    def log(self, text):
        text = _one_line(text, 300)
        if not text:
            return {}
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%SZ")
        self._append("progress.md", f"- {stamp} {text}", MAX_PLAN_BYTES,
                     keep_lines=MAX_PROGRESS_LINES)
        return {"logged": text}

    # -- prompt and gate ----------------------------------------------
    def summary(self, limit=1200):
        status = self.status()
        if not status["total"]:
            return ""
        lines = [f"PLAN ON DISK: {status['done']}/{status['total']} phases done"]
        for index, phase in enumerate(status["phases"][:12]):
            lines.append(f"{index}. [{'x' if phase['done'] else ' '}] {phase['text']}")
        try:
            findings = self.path("findings.md").read_text(encoding="utf-8").strip().splitlines()
            tail = [line for line in findings if line and not line.startswith("#")][-2:]
            if tail:
                lines.append("Latest findings: " + " | ".join(line[:160] for line in tail))
        except OSError:
            pass
        text = "\n".join(lines)
        return text[:limit]

    def gate(self):
        """May the job finish? Unchecked phases block once, then the caller decides."""
        status = self.status()
        unchecked = [phase["text"] for phase in status["phases"] if not phase["done"]]
        if not unchecked:
            return {"allow": True, "unchecked": [], "reason": ""}
        return {"allow": False, "unchecked": unchecked,
                "reason": "Unchecked phases: " + "; ".join(unchecked[:6])}

    def read_all(self):
        result = {}
        for name in ("task_plan.md", "findings.md", "progress.md"):
            try:
                result[name] = self.path(name).read_text(encoding="utf-8")
            except OSError:
                result[name] = ""
        return result

