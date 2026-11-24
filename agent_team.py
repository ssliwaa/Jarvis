"""Multi-agent project rooms, git worktrees, live chat/ask bus, test gate, and orchestration.

Capabilities:
1. Per-agent git worktrees (`worktrees/<agent>/`) mounted RW in bwrap while canonical
   `repo/` and sibling worktrees stay read-only, followed by automatic `git merge`
   and conflict detection on completion.
2. Live JSONL chat bus + synchronous `jarvis-team ask <agent> "..." --wait <sec>`
   and `jarvis-team reply <req_id> "..."` backed by reactive host-side auto-wake
   for idle agents and `@agent` mentions.
3. Optional Architect phase (`plan_first=True` / `mode="plan_then_parallel"`) that
   scaffolds interfaces and `PLAN.json` before launching the parallel swarm.
4. Deterministic syntax & unit-test gate (`py_compile` + `unittest`) executed before
   AI Code Review so broken code bounces straight to a fix round without wasting tokens.
5. Hard project budgets (`max_total_runs`, `max_project_minutes`) preventing runaway loops.
"""

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import agent_cli

PROJECT_ID_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{1,47}$')
MENTION_RE = re.compile(r'@([a-z0-9_-]+)', re.I)
DEFAULT_MAX_ROUNDS = 3
DEFAULT_MAX_TOTAL_RUNS = 12
DEFAULT_MAX_PROJECT_MINUTES = 30
LOCK_TTL_SECONDS = 1800
MAX_CHAT_READ = 200
MAX_MESSAGE_CHARS = 6000

DEFAULT_ROLE_ORDER = (
    ('architect', 'Architekt i integrator — definiuje strukturę, kontrakty API oraz spina moduły.'),
    ('backend', 'Inżynier backendu i logiki — implementuje moduły serwerowe, dane i narzędzia CLI.'),
    ('frontend', 'Inżynier interfejsu i UX — buduje warstwę prezentacji, style i interakcje.'),
    ('qa', 'Inżynier jakości i testów — pisze testy, weryfikuje integrację i zgłasza poprawki.'),
)


class TeamError(Exception):
    """Raised when a multi-agent project action is invalid or unsafe."""


_ORCHESTRATOR_LOCK = threading.Lock()
_WATCHERS_LOCK = threading.Lock()
_ACTIVE_WATCHERS: set[str] = set()


def _team_cli_script() -> str:
    """Self-contained helper CLI mounted read-only inside bwrap at bin/jarvis-team."""
    return '''#!/usr/bin/env python3
"""In-sandbox CLI for multi-agent chat, synchronous ask/reply, board, and file claims."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
import time
import uuid


def _proj_dir() -> Path:
    raw = os.environ.get("JARVIS_TEAM_DIR") or ""
    if not raw:
        sys.stderr.write("jarvis-team: JARVIS_TEAM_DIR is not set.\\n")
        sys.exit(2)
    return Path(raw)


def _locked(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _norm_rel(raw: str) -> str:
    clean = str(raw or "").strip().replace("\\\\", "/").lstrip("/")
    parts = [p for p in clean.split("/") if p and p != "."]
    if not parts or ".." in parts:
        raise ValueError(f"Invalid relative repo path: {raw!r}")
    return "/".join(parts)


def _append_chat(proj: Path, sender: str, role: str, to: str, kind: str, text: str) -> dict:
    chat_dir = proj / "chat"
    fd = _locked(chat_dir / ".lock")
    try:
        now = time.time()
        msg = {
            "id": uuid.uuid4().hex[:10],
            "ts": round(now, 3),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
            "sender": sender,
            "role": role,
            "to": to,
            "kind": kind,
            "text": text[:6000],
        }
        with open(chat_dir / "messages.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg, ensure_ascii=False) + "\\n")
        return msg
    finally:
        os.close(fd)


def cmd_say(args) -> int:
    proj = _proj_dir()
    agent = os.environ.get("JARVIS_TEAM_AGENT") or "agent"
    role = os.environ.get("JARVIS_TEAM_ROLE") or ""
    text = " ".join(args.message).strip()
    if not text:
        sys.stderr.write("jarvis-team say: message cannot be empty.\\n")
        return 1
    msg = _append_chat(proj, agent, role, (args.to or "all").strip(), (args.kind or "chat").strip(), text)
    print(f"[chat:{msg['id']}] {agent} -> {msg['to']}: {msg['text'][:120]}")
    return 0


def cmd_ask(args) -> int:
    proj = _proj_dir()
    sender = os.environ.get("JARVIS_TEAM_AGENT") or "agent"
    role = os.environ.get("JARVIS_TEAM_ROLE") or ""
    target = str(args.target or "").strip().lower().lstrip("@")
    question = " ".join(args.message).strip()
    if not target or not question:
        sys.stderr.write("jarvis-team ask: target and question are required.\\n")
        return 1

    req_id = uuid.uuid4().hex[:10]
    req_dir = proj / "requests"
    fd = _locked(req_dir / ".lock")
    now = round(time.time(), 3)
    try:
        req = {
            "id": req_id,
            "from": sender,
            "to": target,
            "question": question[:4000],
            "created_at": now,
            "status": "pending",
        }
        (req_dir / f"req-{req_id}.json").write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        os.close(fd)

    _append_chat(proj, sender, role, target, "question", f"[ask:{req_id}] {question}")
    wait_s = max(0, min(int(args.wait or 0), 300))
    if wait_s <= 0:
        print(f"[ask:{req_id}] Wysłano pytanie do {target} (bez oczekiwania).")
        return 0

    resp_path = req_dir / f"resp-{req_id}.json"
    msg_file = proj / "chat" / "messages.jsonl"
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if resp_path.is_file():
            try:
                resp = json.loads(resp_path.read_text(encoding="utf-8"))
                print(resp.get("answer") or "")
                return 0
            except (OSError, ValueError):
                pass
        if msg_file.is_file():
            try:
                for line in reversed(msg_file.read_text(encoding="utf-8", errors="replace").splitlines()):
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if float(row.get("ts") or 0) <= now:
                        break
                    if row.get("sender") == target and row.get("to") in ("all", sender, f"@{sender}"):
                        print(row.get("text") or "")
                        return 0
            except (OSError, ValueError):
                pass
        time.sleep(0.25)

    sys.stderr.write(f"[ask:{req_id}] Brak odpowiedzi od {target} w ciągu {wait_s} s.\\n")
    return 124


def cmd_reply(args) -> int:
    proj = _proj_dir()
    sender = os.environ.get("JARVIS_TEAM_AGENT") or "agent"
    role = os.environ.get("JARVIS_TEAM_ROLE") or ""
    req_id = str(args.req_id or "").strip()
    answer = " ".join(args.message).strip()
    if not req_id or not answer:
        sys.stderr.write("jarvis-team reply: req_id and message are required.\\n")
        return 1
    req_dir = proj / "requests"
    req_file = req_dir / f"req-{req_id}.json"
    to_agent = "all"
    fd = _locked(req_dir / ".lock")
    try:
        if req_file.is_file():
            try:
                req = json.loads(req_file.read_text(encoding="utf-8"))
                to_agent = req.get("from") or "all"
                req["status"] = "answered"
                req_file.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding="utf-8")
            except (OSError, ValueError):
                pass
        resp = {
            "id": req_id,
            "from": sender,
            "to": to_agent,
            "answer": answer[:6000],
            "answered_at": round(time.time(), 3),
        }
        (req_dir / f"resp-{req_id}.json").write_text(json.dumps(resp, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        os.close(fd)
    _append_chat(proj, sender, role, to_agent, "answer", f"[reply:{req_id}] {answer}")
    print(f"[reply:{req_id}] Odpowiedziano do {to_agent}.")
    return 0


def cmd_chat(args) -> int:
    proj = _proj_dir()
    msg_file = proj / "chat" / "messages.jsonl"
    if not msg_file.is_file():
        print("(brak wiadomości na czacie projektu)")
        return 0
    rows = []
    for line in msg_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    me = os.environ.get("JARVIS_TEAM_AGENT") or ""
    if args.mine and me:
        rows = [r for r in rows if r.get("to") in ("all", me, f"@{me}") or r.get("sender") == me]
    rows = rows[-max(1, min(args.last, 100)):]
    if not rows:
        print("(brak pasujących wiadomości)")
        return 0
    for r in rows:
        role_tag = f"/{r['role']}" if r.get("role") else ""
        target = f" -> {r['to']}" if r.get("to") and r.get("to") != "all" else ""
        print(f"[{r.get('iso', '')}] ({r.get('kind', 'chat')}) {r.get('sender', '?')}{role_tag}{target}: {r.get('text', '')}")
    return 0


def cmd_board(args) -> int:
    board = _proj_dir() / "BOARD.md"
    if args.write:
        content = Path(args.write).read_text(encoding="utf-8") if Path(args.write).is_file() else args.write
        try:
            fd = _locked(_proj_dir() / "chat" / ".board.lock")
            try:
                board.write_text(content.rstrip() + "\\n", encoding="utf-8")
            finally:
                os.close(fd)
            print("Zaktualizowano BOARD.md")
            return 0
        except OSError:
            # In strict worktree mode BOARD.md may be read-only; publish proposal to chat
            _append_chat(_proj_dir(), os.environ.get("JARVIS_TEAM_AGENT") or "agent", "", "all", "plan", content[:4000])
            print("Opublikowano aktualizację planu na czacie zespołu.")
            return 0
    if not board.is_file():
        print("(brak BOARD.md)")
        return 0
    print(board.read_text(encoding="utf-8", errors="replace"))
    return 0


def _load_claims(claims_path: Path) -> dict:
    try:
        data = json.loads(claims_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _prune_expired(claims: dict) -> dict:
    now = time.time()
    return {
        path: info for path, info in claims.items()
        if isinstance(info, dict) and float(info.get("expires_at") or 0) > now
    }


def cmd_claim(args) -> int:
    proj = _proj_dir()
    agent = os.environ.get("JARVIS_TEAM_AGENT") or "agent"
    locks_dir = proj / "locks"
    claims_path = locks_dir / "claims.json"
    fd = _locked(locks_dir / ".lock")
    try:
        claims = _prune_expired(_load_claims(claims_path))
        wanted = [_norm_rel(p) for p in args.paths]
        conflicts = []
        for rel in wanted:
            for held_path, info in claims.items():
                owner = info.get("agent")
                if owner == agent:
                    continue
                if rel == held_path or rel.startswith(held_path.rstrip("/") + "/") or held_path.startswith(rel.rstrip("/") + "/"):
                    conflicts.append((rel, held_path, owner))
        if conflicts:
            for rel, held, owner in conflicts:
                sys.stderr.write(f"CONFLICT: '{rel}' jest obecnie zablokowane przez '{owner}' ({held}). Uzgodnij na czacie!\\n")
            return 1
        now = time.time()
        for rel in wanted:
            claims[rel] = {
                "agent": agent,
                "claimed_at": round(now, 3),
                "expires_at": round(now + 1800, 3),
                "note": (args.note or "")[:160],
            }
        claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
        print("Zarezerwowano ścieżki: " + ", ".join(wanted))
        return 0
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\\n")
        return 2
    finally:
        os.close(fd)


def cmd_release(args) -> int:
    proj = _proj_dir()
    agent = os.environ.get("JARVIS_TEAM_AGENT") or "agent"
    locks_dir = proj / "locks"
    claims_path = locks_dir / "claims.json"
    fd = _locked(locks_dir / ".lock")
    try:
        claims = _prune_expired(_load_claims(claims_path))
        if args.all or not args.paths:
            removed = [k for k, v in claims.items() if v.get("agent") == agent]
            for k in removed:
                claims.pop(k, None)
        else:
            removed = []
            for raw in args.paths:
                rel = _norm_rel(raw)
                if claims.get(rel, {}).get("agent") == agent:
                    claims.pop(rel, None)
                    removed.append(rel)
        claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
        print("Zwolniono blokady: " + (", ".join(removed) if removed else "(brak)"))
        return 0
    finally:
        os.close(fd)


def cmd_locks(_args) -> int:
    claims_path = _proj_dir() / "locks" / "claims.json"
    claims = _prune_expired(_load_claims(claims_path))
    if not claims:
        print("(brak aktywnych blokad plików)")
        return 0
    for rel, info in sorted(claims.items()):
        note = f" — {info['note']}" if info.get("note") else ""
        print(f"- {rel}: {info.get('agent', '?')}{note}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="jarvis-team")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_say = sub.add_parser("say", help="Wyślij wiadomość na czat zespołu")
    p_say.add_argument("message", nargs="+")
    p_say.add_argument("--to", default="all")
    p_say.add_argument("--kind", default="chat", choices=["chat", "plan", "question", "answer", "review", "done"])
    p_say.set_defaults(func=cmd_say)

    p_ask = sub.add_parser("ask", help="Zadaj pytanie koledze (z auto-budzeniem) i zaczekaj na odpowiedź")
    p_ask.add_argument("target")
    p_ask.add_argument("message", nargs="+")
    p_ask.add_argument("--wait", type=int, default=90)
    p_ask.set_defaults(func=cmd_ask)

    p_rep = sub.add_parser("reply", help="Odpowiedz na pytanie o podanym ID")
    p_rep.add_argument("req_id")
    p_rep.add_argument("message", nargs="+")
    p_rep.set_defaults(func=cmd_reply)

    p_chat = sub.add_parser("chat", help="Odczytaj ostatnie wiadomości zespołu")
    p_chat.add_argument("--last", type=int, default=25)
    p_chat.add_argument("--mine", action="store_true")
    p_chat.set_defaults(func=cmd_chat)

    p_board = sub.add_parser("board", help="Pokaż lub nadpisz wspólną tablicę BOARD.md")
    p_board.add_argument("--write", default="")
    p_board.set_defaults(func=cmd_board)

    p_claim = sub.add_parser("claim", help="Zablokuj pliki/katalogi w repo przed edycją równoległą")
    p_claim.add_argument("paths", nargs="+")
    p_claim.add_argument("--note", default="")
    p_claim.set_defaults(func=cmd_claim)

    p_rel = sub.add_parser("release", help="Zwolnij blokady plików")
    p_rel.add_argument("paths", nargs="*")
    p_rel.add_argument("--all", action="store_true")
    p_rel.set_defaults(func=cmd_release)

    p_locks = sub.add_parser("locks", help="Wypisz aktywne blokady plików")
    p_locks.set_defaults(func=cmd_locks)

    ns = parser.parse_args()
    return ns.func(ns)


if __name__ == "__main__":
    sys.exit(main())
'''


def _slugify(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', str(text or '').lower()).strip('-')[:28]
    suffix = uuid.uuid4().hex[:6]
    base = f'{slug}-{suffix}' if slug else f'proj-{suffix}'
    return base if len(base) >= 4 else f'proj-{base}'


def _validate_project_id(project_id: str) -> str:
    pid = str(project_id or '').strip().lower()
    if not PROJECT_ID_RE.match(pid):
        raise TeamError(f'Invalid project_id: {project_id!r}')
    return pid


def project_root(project_id: str) -> Path:
    pid = _validate_project_id(project_id)
    return agent_cli.projects_root() / pid


@contextmanager
def _file_lock(lock_path: Path):
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _norm_rel_path(raw: str) -> str:
    clean = str(raw or '').strip().replace('\\', '/').lstrip('/')
    parts = [p for p in clean.split('/') if p and p != '.']
    if not parts or '..' in parts:
        raise TeamError(f'Unsafe relative path: {raw!r}')
    return '/'.join(parts)


def _git_available() -> bool:
    return bool(shutil.which('git'))


def _git(cwd: Path, *args: str, timeout: int = 20) -> subprocess.CompletedProcess:
    env = {
        'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
        'HOME': str(cwd),
        'GIT_AUTHOR_NAME': 'Jarvis Team',
        'GIT_AUTHOR_EMAIL': 'jarvis-team@local',
        'GIT_COMMITTER_NAME': 'Jarvis Team',
        'GIT_COMMITTER_EMAIL': 'jarvis-team@local',
        'GIT_TERMINAL_PROMPT': '0',
    }
    return subprocess.run(
        ['git', *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _ensure_git_repo(pdir: Path) -> bool:
    """Initialize repo/ as a local git repo with an initial commit so git worktrees work."""
    if not _git_available():
        return False
    repo = pdir / 'repo'
    repo.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (repo / '.git').exists():
        r = _git(repo, 'init', '-b', 'main')
        if r.returncode != 0:
            _git(repo, 'init')
            _git(repo, 'checkout', '-b', 'main')
        _git(repo, 'config', 'commit.gpgsign', 'false')
        gi = repo / '.gitignore'
        if not gi.exists():
            gi.write_text('__pycache__/\n*.pyc\n.DS_Store\n', encoding='utf-8')
        _git(repo, 'add', '-A')
        _git(repo, 'commit', '--allow-empty', '-m', 'Initial team project repository')
    return (repo / '.git').exists()


def prepare_agent_worktree(project_id: str, agent_id: str, round_no: int) -> Path:
    """Create or reset an isolated git worktree for agent_id based on repo/ HEAD."""
    pdir = project_root(project_id)
    if not _ensure_git_repo(pdir):
        return pdir / 'repo'
    repo = pdir / 'repo'
    wt_dir = pdir / 'worktrees' / agent_id
    branch = f'team/{agent_id}/r{round_no}'

    with _file_lock(pdir / '.git.lock'):
        # Commit any unstaged host-side seed files on main first
        status_main = _git(repo, 'status', '--porcelain')
        if status_main.stdout.strip():
            _git(repo, 'add', '-A')
            _git(repo, 'commit', '-m', f'Sync repo before round {round_no}')

        if wt_dir.exists():
            _git(repo, 'worktree', 'remove', '--force', str(wt_dir))
            if wt_dir.exists():
                shutil.rmtree(wt_dir, ignore_errors=True)
        _git(repo, 'worktree', 'prune')
        wt_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        res = _git(repo, 'worktree', 'add', '-B', branch, str(wt_dir), 'HEAD')
        if res.returncode != 0:
            return repo
    return wt_dir


def merge_agent_worktree(project_id: str, agent_id: str, round_no: int) -> dict:
    """Commit agent's worktree changes on host and merge into canonical repo/ main."""
    pdir = project_root(project_id)
    wt_dir = pdir / 'worktrees' / agent_id
    repo = pdir / 'repo'
    branch = f'team/{agent_id}/r{round_no}'
    if not wt_dir.is_dir() or not (repo / '.git').exists():
        return {'merged': True, 'changed_files': [], 'conflicts': []}

    with _file_lock(pdir / '.git.lock'):
        base_res = _git(repo, 'rev-parse', 'HEAD')
        base = (base_res.stdout or '').strip()

        st = _git(wt_dir, 'status', '--porcelain')
        if st.stdout.strip():
            _git(wt_dir, 'add', '-A')
            _git(wt_dir, 'commit', '-m', f'[{agent_id}] round {round_no} changes')

        # The agent may have committed its own work on the branch (a coding CLI
        # working in a real worktree usually does). A clean worktree is not an
        # empty delivery: merge whatever the branch is ahead by, or that work is
        # silently lost and the gate only sees an unchanged repo/.
        ahead_n = 0
        if base:
            ahead = _git(repo, 'rev-list', '--count', f'{base}..{branch}')
            try:
                ahead_n = int((ahead.stdout or '0').strip() or 0)
            except ValueError:
                ahead_n = 0
        if ahead_n == 0:
            return {'merged': True, 'changed_files': [], 'conflicts': []}

        diff_names = _git(repo, 'diff', '--name-only', f'{base}...{branch}')
        changed = [ln.strip() for ln in diff_names.stdout.splitlines() if ln.strip()]

        merge_res = _git(repo, 'merge', '--no-edit', branch)
        if merge_res.returncode == 0:
            return {'merged': True, 'changed_files': changed, 'conflicts': [], 'branch': branch}

        unmerged = _git(repo, 'diff', '--name-only', '--diff-filter=U')
        conflicts = [ln.strip() for ln in unmerged.stdout.splitlines() if ln.strip()]
        if not conflicts:
            conflicts = changed or [branch]
        _git(repo, 'merge', '--abort')
        return {
            'merged': False,
            'changed_files': changed,
            'conflicts': conflicts,
            'branch': branch,
            'detail': (merge_res.stdout + '\n' + merge_res.stderr).strip()[:600],
        }


TEST_DIR_SKIP = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build',
                 '.mypy_cache', '.pytest_cache', 'site-packages'}

# A restart kills the bwrap wrappers, but the inner CLI can keep writing for a while.
# Wait until the room has been quiet this long before declaring the wave dead.
RECONCILE_GRACE_SECONDS = 90
_RECONCILING = set()
_RECONCILE_LOCK = threading.Lock()


def _wave_quiet_seconds(pdir: Path) -> float:
    """Seconds since the room last produced anything (chat bus + run logs)."""
    newest = 0.0
    for path in (pdir / 'chat' / 'messages.jsonl', pdir / 'project.json'):
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    if not newest:
        return 1e9
    return time.time() - newest


def reconcile_stale_runs(project_id: str, require_quiet: bool = True) -> dict:
    """Finish a wave whose member processes are gone instead of hanging the room.

    A Jarvis restart kills the sandbox wrappers: the runs are recorded ``failed``
    with ``rc=None``, but ``active_runs`` in project.json still lists the members,
    so the project stays ``running`` forever, their branches are never merged and
    the deterministic gate never runs. This merges what they committed and lets the
    normal gate/review path decide the outcome.
    """
    pdir = project_root(project_id)
    if not (pdir / 'project.json').is_file():
        raise TeamError(f'Team project does not exist: {project_id}')

    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        active = dict(meta.get('active_runs') or {})
        if not active:
            return {'ok': True, 'reconciled': [], 'note': 'no active runs'}

        alive, dead = {}, {}
        for aid, info in active.items():
            try:
                running = bool(agent_cli.live_progress(aid).get('running'))
            except Exception:
                running = False
            (alive if running else dead)[aid] = info
        if not dead:
            return {'ok': True, 'reconciled': [], 'note': 'every member is still alive'}

        quiet = _wave_quiet_seconds(pdir)
        if require_quiet and quiet < RECONCILE_GRACE_SECONDS:
            return {'ok': True, 'reconciled': [], 'deferred': True,
                    'note': f'room wrote {int(quiet)} s ago; waiting for {RECONCILE_GRACE_SECONDS} s of silence'}

        meta['active_runs'] = alive
        if not alive and str(meta.get('status')) == 'running':
            meta['status'] = 'interrupted'
        meta['updated_at'] = time.time()
        _save_meta(pdir, meta)
        round_no = int(meta.get('current_round') or 1)
        phase = str(meta.get('phase') or 'build')

    merged = {}
    for aid in sorted(dead):
        try:
            merged[aid] = merge_agent_worktree(project_id, aid, round_no)
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            merged[aid] = {'merged': False, 'changed_files': [], 'conflicts': [], 'error': str(exc)[:200]}

    details = []
    for aid, info in merged.items():
        if info.get('merged') is False:
            details.append(f"{aid}: konflikt w {', '.join(info.get('conflicts') or []) or '?'}")
        elif info.get('changed_files'):
            details.append(f"{aid}: scalono {len(info['changed_files'])} plików")
        else:
            details.append(f"{aid}: brak zmian do scalenia")

    # Remember what the recovery produced: without it the gate would judge the round
    # by runs recorded `failed` (the restart artifact) and refuse to close the project.
    recovered_files = sum(len(i.get('changed_files') or []) for i in merged.values())
    conflicts = [
        {'round': round_no, 'agent': aid, 'branch': i.get('branch', ''), 'files': i.get('conflicts') or []}
        for aid, i in merged.items() if i.get('merged') is False
    ]
    with _file_lock(pdir / '.meta.lock'):
        fresh = _load_meta(pdir)
        if recovered_files:
            fresh['recovered_wave'] = True
        if conflicts:
            fresh['merge_conflicts'] = list(fresh.get('merge_conflicts') or []) + conflicts
        _save_meta(pdir, fresh)

    post_message(
        project_id,
        sender='jarvis',
        kind='system',
        text=("Procesy fali zniknęły (restart Jarvisa?) — posprzątałem stan i scaliłem to, co zdążyły "
              f"zacommitować. {'; '.join(details)}"),
        _trigger_wake=False,
    )

    gate_started = False
    if not alive and phase in ('build', 'gate'):
        threading.Thread(target=_evaluate_gate_and_advance, args=(project_id, round_no),
                         daemon=True, name=f'reconcile-gate-{project_id}').start()
        gate_started = True

    return {'ok': True, 'reconciled': sorted(dead), 'merged': merged, 'gate_started': gate_started}


def _maybe_reconcile(project_id: str) -> None:
    """Run ``reconcile_stale_runs`` off the request path, never concurrently."""
    with _RECONCILE_LOCK:
        if project_id in _RECONCILING:
            return
        _RECONCILING.add(project_id)

    def _run():
        try:
            reconcile_stale_runs(project_id)
        except Exception as exc:  # noqa: BLE001 - a broken room must not break status
            print(f'[team] reconcile failed: {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
        finally:
            with _RECONCILE_LOCK:
                _RECONCILING.discard(project_id)

    threading.Thread(target=_run, daemon=True, name=f'reconcile-{project_id}').start()


def _test_directories(repo: Path) -> list[str]:
    """Relative directories under repo/ that hold unittest modules.

    A directory without ``__init__.py`` is not a package, so ``unittest discover``
    from the repo root silently skips it: a plain ``tests/test_*.py`` was reported
    as "NO TESTS RAN" even though 25 tests passed when run directly.
    """
    found = []
    for path in sorted(repo.rglob('*.py')):
        rel_parts = path.relative_to(repo).parts
        if any(part in TEST_DIR_SKIP for part in rel_parts[:-1]):
            continue
        name = path.name
        if not (name.startswith('test_') or name.endswith('_test.py')):
            continue
        rel = path.parent.relative_to(repo)
        key = '.' if str(rel) == '.' else str(rel)
        if key not in found:
            found.append(key)
    return found


def _count_unittest_tests(text: str) -> int:
    match = re.search(r'^Ran (\d+) tests?', str(text or ''), re.M)
    return int(match.group(1)) if match else 0


def run_deterministic_gate(project_id: str, timeout: int = 30) -> dict:
    """Run fast syntax & unit-test verification on repo/ before invoking an AI Reviewer."""
    pdir = project_root(project_id)
    repo = pdir / 'repo'
    if not repo.is_dir():
        return {'ok': True, 'checks': [], 'output': ''}

    checks = []
    outputs = []
    delivered = [
        p for p in repo.rglob('*')
        if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts
        and p.name != '.gitignore'
    ]
    if not delivered:
        # An empty delivery used to pass every check by vacuous truth: the team
        # reported GATE_PASSED while repo/ held nothing but .gitignore.
        return {
            'ok': False,
            'checks': [{'name': 'empty_delivery', 'ok': False}],
            'output': ('Repozytorium projektu nie zawiera żadnych plików poza .gitignore — '
                       'fala nie dostarczyła zmian do repo/.'),
        }

    py_files = [
        p for p in sorted(repo.rglob('*.py'))
        if '.git' not in p.parts and '__pycache__' not in p.parts
    ]
    if py_files:
        rel_py = [str(p.relative_to(repo)) for p in py_files[:80]]
        try:
            r_comp = subprocess.run(
                [sys.executable, '-m', 'py_compile', *rel_py],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            checks.append({'name': 'py_compile', 'ok': False})
            outputs.append(f'py_compile: przekroczono limit {timeout} s.')
        else:
            ok_comp = r_comp.returncode == 0
            checks.append({'name': 'py_compile', 'ok': ok_comp})
            if not ok_comp:
                outputs.append((r_comp.stdout + '\n' + r_comp.stderr).strip())

    test_dirs = _test_directories(repo)
    if test_dirs and all(c['ok'] for c in checks):
        ran_total = 0
        failed = False
        for rel_dir in test_dirs:
            try:
                r_ut = subprocess.run(
                    # `discover` from the repo root only walks packages (a directory
                    # needs __init__.py), so a plain tests/ with test_*.py reported
                    # "NO TESTS RAN" while 25 tests passed when run directly.
                    [sys.executable, '-m', 'unittest', 'discover',
                     '-s', rel_dir or '.', '-p', '*test*.py'],
                    cwd=str(repo),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                checks.append({'name': 'unittest', 'ok': False})
                outputs.append(f'unittest ({rel_dir or "."}): przekroczono limit {timeout} s '
                               f'(bramka nie potwierdziła testów).')
                failed = True
                break
            ran_total += _count_unittest_tests(r_ut.stderr or '') + _count_unittest_tests(r_ut.stdout or '')
            if r_ut.returncode != 0:
                failed = True
                outputs.append((r_ut.stdout + '\n' + r_ut.stderr).strip())
        if failed:
            checks.append({'name': 'unittest', 'ok': False})
        elif ran_total == 0:
            # Files named test*.py exist but nothing was collected: say so instead of
            # printing a bare "NO TESTS RAN" the owner cannot act on.
            checks.append({'name': 'unittest', 'ok': False})
            outputs.append('unittest: w ' + ', '.join(test_dirs) + ' są pliki testów, ale nie '
                           'uruchomiono ani jednego testu (sprawdź importy/nazwy klas TestCase).')
        else:
            checks.append({'name': 'unittest', 'ok': True})

    js_files = [
        p for p in sorted(repo.rglob('*.js'))
        if '.git' not in p.parts and 'node_modules' not in p.parts
    ]
    node_bin = shutil.which('node')
    if js_files and node_bin and all(c['ok'] for c in checks):
        for jf in js_files[:25]:
            try:
                r_js = subprocess.run(
                    [node_bin, '--check', str(jf.relative_to(repo))],
                    cwd=str(repo),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                checks.append({'name': f'node_check:{jf.name}', 'ok': False})
                outputs.append(f'node --check {jf.name}: przekroczono limit 10 s.')
                break
            if r_js.returncode != 0:
                checks.append({'name': f'node_check:{jf.name}', 'ok': False})
                outputs.append((r_js.stdout + '\n' + r_js.stderr).strip())
                break
        else:
            checks.append({'name': 'node_check', 'ok': True})

    if all(c['ok'] for c in checks):
        try:
            import security_scanner
            sec_res = security_scanner.scan_directory(repo, include_tests=False)
            checks.append({'name': 'security_scanner', 'ok': bool(sec_res.get('ok'))})
            if not sec_res.get('ok'):
                for f in (sec_res.get('findings') or [])[:8]:
                    outputs.append(f"{f['path']}:{f['line']} [{f['kind']}] {f['detail']}")
        except Exception:
            pass

    if all(c['ok'] for c in checks) and (repo / 'viewer' / 'index.html').is_file():
        try:
            import qa_gate
            qa_res = qa_gate.audit_viewer(repo)
            if not qa_res.get('skipped'):
                checks.append({'name': 'viewer_qa_gate', 'ok': bool(qa_res.get('ok'))})
                if not qa_res.get('ok'):
                    outputs.extend(qa_res.get('issues') or [])
        except Exception:
            pass

    if all(c['ok'] for c in checks):
        try:
            import visual_qa
            vqa = visual_qa.run_visual_qa(repo, screenshot_path=pdir / 'outbox' / 'visual_qa.png')
            if vqa.get('applicable'):
                checks.append({'name': 'visual_qa', 'ok': bool(vqa.get('ok'))})
                if not vqa.get('ok') and vqa.get('output'):
                    outputs.append(vqa['output'])
        except Exception:
            pass

    gate_ok = all(c['ok'] for c in checks)
    return {
        'ok': gate_ok,
        'checks': checks,
        'output': '\n'.join(outputs)[-2500:],
    }


def _ensure_project_layout(pdir: Path) -> None:
    pdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for sub in ('repo', 'worktrees', 'chat', 'locks', 'requests', 'outbox', 'bin'):
        (pdir / sub).mkdir(mode=0o700, parents=True, exist_ok=True)
    cli_path = pdir / 'bin' / 'jarvis-team'
    script = _team_cli_script()
    if not cli_path.is_file() or cli_path.read_text(encoding='utf-8', errors='replace') != script:
        tmp = cli_path.with_suffix('.tmp')
        tmp.write_text(script, encoding='utf-8')
        os.chmod(tmp, 0o755)
        tmp.replace(cli_path)


def _load_meta(pdir: Path) -> dict:
    meta_path = pdir / 'project.json'
    if not meta_path.is_file():
        raise TeamError(f'Project does not exist: {pdir.name}')
    try:
        data = json.loads(meta_path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise TeamError(f'Corrupted project metadata: {exc}') from None
    if not isinstance(data, dict):
        raise TeamError('Invalid project metadata format.')
    return data


def _save_meta(pdir: Path, meta: dict) -> dict:
    meta['updated_at'] = round(time.time(), 3)
    meta_path = pdir / 'project.json'
    tmp = meta_path.with_suffix('.tmp')
    tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding='utf-8')
    os.chmod(tmp, 0o600)
    tmp.replace(meta_path)
    return meta


def _budget_status(meta: dict) -> dict:
    used = int(meta.get('total_runs') or 0)
    max_runs = int(meta.get('max_total_runs') or DEFAULT_MAX_TOTAL_RUNS)
    max_mins = float(meta.get('max_project_minutes') or DEFAULT_MAX_PROJECT_MINUTES)
    created = float(meta.get('created_at') or time.time())
    deadline = created + max_mins * 60.0
    rem_sec = round(max(0.0, deadline - time.time()), 1)
    exhausted = used >= max_runs or rem_sec <= 0.0
    reason = ''
    if used >= max_runs:
        reason = f'Osiągnięto limit uruchomień projektu ({used}/{max_runs}).'
    elif rem_sec <= 0.0:
        reason = f'Przekroczono limit czasu projektu ({int(max_mins)} min).'
    return {
        'allowed': not exhausted,
        'used_runs': used,
        'max_total_runs': max_runs,
        'max_project_minutes': max_mins,
        'remaining_seconds': rem_sec,
        'reason': reason,
    }


def create_project(goal: str, participants=None, title: str = '', project_id: str = '',
                   mode: str = 'parallel', max_rounds: int = DEFAULT_MAX_ROUNDS,
                   max_total_runs: int = DEFAULT_MAX_TOTAL_RUNS,
                   max_project_minutes: int = DEFAULT_MAX_PROJECT_MINUTES,
                   use_worktrees: bool = True, auto_wake_mentions: bool = True,
                   seed_dir: str = '') -> dict:
    """Create a shared project room with git repo/, worktrees/, chat/, locks/, requests/, and bin/jarvis-team."""
    if not isinstance(goal, str) or not goal.strip():
        raise TeamError('Project goal is required.')
    if mode not in ('parallel', 'relay', 'plan_then_parallel'):
        raise TeamError("mode must be 'parallel', 'plan_then_parallel', or 'relay'.")

    known = set(agent_cli.agent_ids())
    if participants:
        chosen = []
        for raw_a in participants:
            aid = str(raw_a or '').strip().lower()
            if aid not in known:
                raise TeamError(f'Unknown agent: {aid!r}')
            if aid not in chosen:
                chosen.append(aid)
    else:
        try:
            import agent_router
            chosen = [r['agent'] for r in agent_router.select_team(goal, max_members=3)]
        except Exception:
            chosen = []
        if not chosen:
            chosen = [a for a in agent_cli.agent_ids() if agent_cli.binary_present(a)]
        if not chosen:
            chosen = list(agent_cli.agent_ids()[:2])

    pid = _validate_project_id(project_id) if project_id else _slugify(title or goal[:32])
    pdir = project_root(pid)
    if (pdir / 'project.json').exists():
        raise TeamError(f'Project already exists: {pid}')

    _ensure_project_layout(pdir)

    if seed_dir:
        src = Path(seed_dir).expanduser().resolve()
        if not src.is_dir():
            raise TeamError(f'seed_dir is not a directory: {seed_dir}')
        _copy_seed_tree(src, pdir / 'repo')

    git_ready = _ensure_git_repo(pdir) if use_worktrees else False

    now = round(time.time(), 3)
    clean_title = (title or goal.strip().splitlines()[0])[:120]
    meta = {
        'id': pid,
        'title': clean_title,
        'goal': goal.strip()[:4000],
        'mode': mode,
        'status': 'ready',
        'phase': 'idle',
        'participants': chosen,
        'current_round': 0,
        'max_rounds': max(1, min(int(max_rounds or DEFAULT_MAX_ROUNDS), 8)),
        'total_runs': 0,
        'max_total_runs': max(2, min(int(max_total_runs or DEFAULT_MAX_TOTAL_RUNS), 60)),
        'max_project_minutes': max(2, min(int(max_project_minutes or DEFAULT_MAX_PROJECT_MINUTES), 240)),
        'use_worktrees': bool(use_worktrees and git_ready),
        'auto_wake_mentions': bool(auto_wake_mentions),
        'created_at': now,
        'updated_at': now,
        'active_runs': {},
        'assignments': [],
        'review_agent': '',
        'auto_fallback': True,
        'merge_conflicts': [],
        'last_gate': None,
        'history': [],
    }

    with _file_lock(pdir / '.meta.lock'):
        _save_meta(pdir, meta)
        board_lines = [
            f'# PROJEKT ZESPOŁOWY: {clean_title}',
            f'- ID projektu: `{pid}`',
            f'- Tryb współpracy: `{mode}` (git worktrees: `{"tak" if meta["use_worktrees"] else "nie"}`)',
            f'- Uczestnicy: {", ".join(f"`{a}`" for a in chosen)}',
            '',
            '## Cel główny',
            goal.strip(),
            '',
            '## Aktualny podział zadań i kontrakty',
            '_(Uzupełniane przez Architekta, orkiestrator i agentów w trakcie pracy)_',
        ]
        (pdir / 'BOARD.md').write_text('\n'.join(board_lines) + '\n', encoding='utf-8')

    post_message(
        pid,
        sender='jarvis',
        kind='system',
        text=f'Utworzono pokój projektu "{clean_title}" (tryb: {mode}, worktree: {meta["use_worktrees"]}, zespół: {", ".join(chosen)}).',
        _trigger_wake=False,
    )
    return project_status(pid)


def _copy_seed_tree(src: Path, dst: Path) -> None:
    skip = {
        '.git', 'node_modules', '.venv', 'venv', '__pycache__',
        '.jarvis-mcp-backups', 'artifacts', '.orbit-backup',
        '.pytest_cache', '.mypy_cache', '.ruff_cache',
    }
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith('.jarvis-')]
        rel_root = Path(root).relative_to(src)
        target_dir = dst / rel_root
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in files:
            if fname in ('.env', 'secrets.json') or fname.endswith(('.pem', '.key')):
                continue
            sfile = Path(root) / fname
            if sfile.is_symlink() or sfile.stat().st_size > 2_000_000:
                continue
            shutil.copy2(sfile, target_dir / fname)


def post_message(project_id: str, sender: str, text: str, to: str = 'all',
                 kind: str = 'chat', role: str = '', _trigger_wake: bool = True) -> dict:
    """Append an atomic message to chat/messages.jsonl and optionally wake @mentioned idle agents."""
    pdir = project_root(project_id)
    if not (pdir / 'project.json').is_file():
        raise TeamError(f'Project does not exist: {project_id}')
    clean_text = str(text or '').strip()
    if not clean_text:
        raise TeamError('Message text cannot be empty.')
    now = time.time()
    msg = {
        'id': uuid.uuid4().hex[:10],
        'ts': round(now, 3),
        'iso': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(now)),
        'sender': str(sender or 'user').strip()[:40],
        'role': str(role or '').strip()[:40],
        'to': str(to or 'all').strip()[:40],
        'kind': str(kind or 'chat').strip()[:24],
        'text': clean_text[:MAX_MESSAGE_CHARS],
    }
    chat_dir = pdir / 'chat'
    with _file_lock(chat_dir / '.lock'):
        with open(chat_dir / 'messages.jsonl', 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(msg, ensure_ascii=False) + '\n')

    try:
        import event_bus
        event_bus.publish('team.message', {'project_id': project_id, **msg})
    except Exception:
        pass

    if _trigger_wake and sender not in ('jarvis', 'system'):
        _maybe_queue_mention_wake(project_id, msg)
    return msg


def _maybe_queue_mention_wake(project_id: str, msg: dict) -> None:
    pdir = project_root(project_id)
    try:
        meta = _load_meta(pdir)
    except TeamError:
        return
    if not meta.get('auto_wake_mentions', True):
        return
    known = set(agent_cli.agent_ids())
    targets = set()
    to_val = str(msg.get('to') or '').lstrip('@').lower()
    if to_val in known and msg.get('kind') == 'question':
        targets.add(to_val)
    for m in MENTION_RE.findall(msg.get('text') or ''):
        cand = m.lower()
        if cand in known and cand != msg.get('sender'):
            targets.add(cand)
    if not targets:
        return
    req_dir = pdir / 'requests'
    for target in targets:
        if target == msg.get('sender'):
            continue
        # Skip if already created via jarvis-team ask
        if '[ask:' in (msg.get('text') or ''):
            continue
        req_id = f"m-{msg['id']}-{target[:4]}"
        req_path = req_dir / f'req-{req_id}.json'
        with _file_lock(req_dir / '.lock'):
            if not req_path.exists():
                req_path.write_text(json.dumps({
                    'id': req_id,
                    'from': msg.get('sender') or 'owner',
                    'to': target,
                    'question': msg.get('text') or '',
                    'created_at': msg.get('ts') or time.time(),
                    'status': 'pending',
                }, ensure_ascii=False, indent=2), encoding='utf-8')
    process_pending_requests(project_id)


def process_pending_requests(project_id: str) -> list[dict]:
    """Dispatch lightweight responder runs for pending `jarvis-team ask` or `@mention` questions."""
    pdir = project_root(project_id)
    req_dir = pdir / 'requests'
    if not req_dir.is_dir():
        return []
    dispatched = []
    for req_file in sorted(req_dir.glob('req-*.json')):
        target = ''
        req = None
        with _file_lock(req_dir / '.lock'):
            try:
                req = json.loads(req_file.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if not isinstance(req, dict) or req.get('status') != 'pending':
                continue
            target = str(req.get('to') or '').strip().lower()
            if target in ('owner', 'user'):
                try:
                    import voice_bridge
                    voice_bridge.enqueue_owner_question(
                        project_id,
                        str(req.get('id') or ''),
                        str(req.get('from') or 'agent'),
                        str(req.get('question') or ''),
                    )
                    req['status'] = 'awaiting_owner'
                    req_file.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding='utf-8')
                except Exception:
                    pass
                continue
            if target not in set(agent_cli.agent_ids()) or not agent_cli.binary_present(target):
                continue
            busy, _ = agent_cli._check_running(target)
            if busy:
                continue
            with _file_lock(pdir / '.meta.lock'):
                meta = _load_meta(pdir)
                if not _budget_status(meta)['allowed']:
                    req['status'] = 'budget_skipped'
                    req_file.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding='utf-8')
                    continue
                meta['total_runs'] = int(meta.get('total_runs') or 0) + 1
                _save_meta(pdir, meta)
            req['status'] = 'dispatched'
            req_file.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding='utf-8')

        if req and target:
            try:
                info = _launch_responder_async(project_id, target, req)
                dispatched.append(info)
            except Exception:
                with _file_lock(req_dir / '.lock'):
                    req['status'] = 'pending'
                    req_file.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding='utf-8')
    return dispatched


def _launch_responder_async(project_id: str, agent_id: str, req: dict) -> dict:
    pdir = project_root(project_id)
    req_id = req['id']
    sender = req.get('from') or 'teammate'
    question = req.get('question') or ''
    prompt = (
        f"Kolega z zespołu (`{sender}`) zadał Ci pilne pytanie w projekcie `{project_id}` (ID pytania: `{req_id}`).\n\n"
        f"Pytanie:\n{question}\n\n"
        f"Instrukcja:\n"
        f"1. Masz podgląd repozytorium projektu w `{pdir / 'repo'}` oraz czatu (`jarvis-team chat --last 15`).\n"
        f"2. Odpowiedz zwięźle i konkretnie komendą:\n"
        f"   `jarvis-team reply {req_id} \"Twoja konkretna odpowiedź techniczna\"`\n"
        f"3. Nie modyfikuj plików kodu — to szybka konsultacja techniczna.\n"
    )
    extra_env = {
        'JARVIS_TEAM_DIR': str(pdir),
        'JARVIS_TEAM_ID': project_id,
        'JARVIS_TEAM_AGENT': agent_id,
        'JARVIS_TEAM_ROLE': 'responder',
        'JARVIS_TEAM_BIN': str(pdir / 'bin'),
    }

    def _on_resp_done(final_rec):
        resp_file = pdir / 'requests' / f'resp-{req_id}.json'
        if not resp_file.is_file():
            fallback_txt = agent_cli.tail(agent_id, final_rec.get('id')).strip()[-1500:] or '(brak treści odpowiedzi)'
            with _file_lock(pdir / 'requests' / '.lock'):
                resp_file.write_text(json.dumps({
                    'id': req_id,
                    'from': agent_id,
                    'to': sender,
                    'answer': fallback_txt,
                    'answered_at': round(time.time(), 3),
                }, ensure_ascii=False, indent=2), encoding='utf-8')
            post_message(
                project_id,
                sender=agent_id,
                to=sender,
                role='responder',
                kind='answer',
                text=f'[reply:{req_id}] {fallback_txt[:800]}',
                _trigger_wake=False,
            )

    started = agent_cli.start_async(
        agent_id,
        prompt,
        approved=True,
        timeout=120,
        consent='team-ask',
        cwd=pdir / 'repo',
        extra_rw_paths=[pdir / 'chat', pdir / 'requests'],
        extra_ro_paths=[pdir / 'repo', pdir / 'bin', pdir / 'BOARD.md'],
        extra_env=extra_env,
        raw_prompt=True,
        archive_outbox=False,
        task_label=f'[team:{project_id}/reply:{req_id}] Odpowiedź dla {sender}',
        on_finish=_on_resp_done,
    )
    return {'req_id': req_id, 'agent': agent_id, 'run_id': started['id']}


def _ensure_request_watcher(project_id: str) -> None:
    with _WATCHERS_LOCK:
        if project_id in _ACTIVE_WATCHERS:
            return
        _ACTIVE_WATCHERS.add(project_id)

    def _loop():
        try:
            idle_ticks = 0
            while idle_ticks < 8:
                try:
                    pdir = project_root(project_id)
                    meta = _load_meta(pdir)
                except TeamError:
                    break
                process_pending_requests(project_id)
                has_pending = any(
                    '"pending"' in p.read_text(encoding='utf-8', errors='ignore')
                    for p in (pdir / 'requests').glob('req-*.json')
                )
                if meta.get('active_runs') or has_pending:
                    idle_ticks = 0
                else:
                    idle_ticks += 1
                time.sleep(0.35)
        finally:
            with _WATCHERS_LOCK:
                _ACTIVE_WATCHERS.discard(project_id)

    threading.Thread(target=_loop, name=f'jarvis-team-watch-{project_id[:12]}', daemon=True).start()


def read_messages(project_id: str, limit: int = 50, since_ts: float = 0.0,
                  for_agent: str = '') -> list[dict]:
    """Read recent messages from chat/messages.jsonl."""
    pdir = project_root(project_id)
    msg_path = pdir / 'chat' / 'messages.jsonl'
    if not msg_path.is_file():
        return []
    rows = []
    try:
        lines = msg_path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if since_ts and float(item.get('ts') or 0) <= float(since_ts):
            continue
        if for_agent and item.get('to') not in ('all', for_agent, f'@{for_agent}') and item.get('sender') != for_agent:
            continue
        rows.append(item)
    cap = max(1, min(int(limit or 50), MAX_CHAT_READ))
    return rows[-cap:]


def active_claims(project_id: str) -> dict:
    """Return non-expired file/directory ownership locks."""
    pdir = project_root(project_id)
    claims_path = pdir / 'locks' / 'claims.json'
    if not claims_path.is_file():
        return {}
    try:
        raw = json.loads(claims_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    now = time.time()
    return {
        rel: info for rel, info in raw.items()
        if isinstance(info, dict) and float(info.get('expires_at') or 0) > now
    }


def claim_files(project_id: str, agent_id: str, paths: list[str],
                note: str = '', ttl: int = LOCK_TTL_SECONDS) -> dict:
    """Atomically claim relative repo paths for one agent; rejects overlapping claims."""
    pdir = project_root(project_id)
    if not (pdir / 'project.json').is_file():
        raise TeamError(f'Project does not exist: {project_id}')
    agent_cli._agent(agent_id)
    wanted = [_norm_rel_path(p) for p in (paths or []) if str(p or '').strip()]
    if not wanted:
        return {}

    locks_dir = pdir / 'locks'
    claims_path = locks_dir / 'claims.json'
    with _file_lock(locks_dir / '.lock'):
        claims = active_claims(project_id)
        for rel in wanted:
            for held, info in claims.items():
                owner = info.get('agent')
                if owner == agent_id:
                    continue
                if (rel == held
                        or rel.startswith(held.rstrip('/') + '/')
                        or held.startswith(rel.rstrip('/') + '/')):
                    raise TeamError(
                        f"Path '{rel}' conflicts with active lock '{held}' held by {owner}."
                    )
        now = time.time()
        exp = now + max(60, min(int(ttl or LOCK_TTL_SECONDS), 7200))
        for rel in wanted:
            claims[rel] = {
                'agent': agent_id,
                'claimed_at': round(now, 3),
                'expires_at': round(exp, 3),
                'note': str(note or '')[:160],
            }
        claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding='utf-8')
        return claims


def release_files(project_id: str, agent_id: str, paths: list[str] | None = None) -> list[str]:
    """Release specific or all locks owned by agent_id."""
    pdir = project_root(project_id)
    locks_dir = pdir / 'locks'
    claims_path = locks_dir / 'claims.json'
    if not claims_path.is_file():
        return []
    with _file_lock(locks_dir / '.lock'):
        claims = active_claims(project_id)
        if not paths:
            removed = [rel for rel, info in claims.items() if info.get('agent') == agent_id]
        else:
            norm_targets = {_norm_rel_path(p) for p in paths}
            removed = [
                rel for rel, info in claims.items()
                if info.get('agent') == agent_id and rel in norm_targets
            ]
        for rel in removed:
            claims.pop(rel, None)
        claims_path.write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding='utf-8')
        return removed


def repo_files(project_id: str, subdir: str = 'repo') -> list[dict]:
    """List files inside repo/ or outbox/ of a shared project (excluding .git)."""
    pdir = project_root(project_id)
    target = pdir / ('outbox' if subdir == 'outbox' else 'repo')
    if not target.is_dir():
        return []
    rows = []
    for path in sorted(target.rglob('*')):
        if len(rows) >= 200:
            break
        if '.git' in path.parts or '__pycache__' in path.parts:
            continue
        try:
            if not path.is_file():
                continue
            st = path.stat()
        except OSError:
            continue
        rows.append({
            'path': str(path.relative_to(target)),
            'bytes': st.st_size,
            'modified': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(st.st_mtime)),
        })
    return rows


def sync_repo_to_outbox(project_id: str, summary_note: str = '') -> list[dict]:
    """Export the collaborative repo/ and a synthesized TEAM_SUMMARY.md into project outbox/."""
    pdir = project_root(project_id)
    meta = _load_meta(pdir)
    repo_dir = pdir / 'repo'
    out_dir = pdir / 'outbox'
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    for existing in list(out_dir.iterdir()):
        if existing.is_dir():
            shutil.rmtree(existing, ignore_errors=True)
        else:
            try:
                existing.unlink()
            except OSError:
                pass

    if repo_dir.is_dir():
        _copy_seed_tree(repo_dir, out_dir)

    recent_msgs = read_messages(project_id, limit=30)
    board_text = (pdir / 'BOARD.md').read_text(encoding='utf-8', errors='replace') if (pdir / 'BOARD.md').is_file() else ''
    gate = meta.get('last_gate')
    lines = [
        f"# Podsumowanie pracy zespołu — {meta.get('title', project_id)}",
        f"- Projekt: `{project_id}`",
        f"- Status: `{meta.get('status')}`",
        f"- Uczestnicy: {', '.join(meta.get('participants') or [])}",
        f"- Rundy: {meta.get('current_round', 0)} / {meta.get('max_rounds', DEFAULT_MAX_ROUNDS)}",
        f"- Zużyte uruchomienia budżetu: {meta.get('total_runs', 0)} / {meta.get('max_total_runs', DEFAULT_MAX_TOTAL_RUNS)}",
        "",
    ]
    if gate:
        lines.append(f"- Bramka testów deterministycznych: `{'PASS' if gate.get('ok') else 'FAIL'}`")
        lines.append("")
    if summary_note:
        lines.extend(["## Notatka końcowa", summary_note.strip(), ""])
    if board_text.strip():
        lines.extend(["## Stan tablicy BOARD.md", board_text.strip(), ""])
    if recent_msgs:
        lines.append("## Ostatnie ustalenia z czatu zespołu")
        for m in recent_msgs[-15:]:
            lines.append(f"- **[{m.get('iso', '')}] {m.get('sender', '?')}** ({m.get('kind', 'chat')}): {m.get('text', '')}")
        lines.append("")

    summary_text = "\n".join(lines)
    (out_dir / 'TEAM_SUMMARY.md').write_text(summary_text, encoding='utf-8')
    if not (out_dir / 'outbox.md').exists():
        (out_dir / 'outbox.md').write_text(summary_text, encoding='utf-8')
    return repo_files(project_id, subdir='outbox')


def build_team_prompt(project_id: str, agent_id: str, role: str, subtask: str,
                      work_dir: Path | None = None, owned_paths: list[str] | None = None,
                      teammates: list[str] | None = None) -> str:
    """Construct the collaborative prompt with live BOARD.md, recent chat, locks, and jarvis-team CLI instructions."""
    pdir = project_root(project_id)
    meta = _load_meta(pdir)
    board = (pdir / 'BOARD.md').read_text(encoding='utf-8', errors='replace')[:4500] if (pdir / 'BOARD.md').is_file() else ''
    msgs = read_messages(project_id, limit=20)
    claims = active_claims(project_id)

    chat_block = '\n'.join(
        f"[{m.get('iso', '')}] ({m.get('kind', 'chat')}) {m.get('sender', '?')}: {m.get('text', '')}"
        for m in msgs
    ) or '(brak wcześniejszych wiadomości — zaczynasz rozmowę)'

    locks_block = '\n'.join(
        f"- {rel}: zablokowane przez `{info.get('agent')}`"
        for rel, info in sorted(claims.items())
    ) or '(brak aktywnych blokad)'

    peers = [a for a in (teammates or meta.get('participants') or []) if a != agent_id]
    peers_str = ', '.join(peers) if peers else 'brak (pracujesz samodzielnie w tej fazie)'
    owned_str = ', '.join(owned_paths) if owned_paths else '(rezerwuj pliki komendą `jarvis-team claim <ścieżka>` przed zapisem)'
    actual_cwd = work_dir or (pdir / 'repo')

    ctx_section = ''
    try:
        import code_index
        ctx_pack = code_index.build_context_pack(subtask, root_dir=actual_cwd, limit=5)
        if ctx_pack:
            ctx_section = f"\n{ctx_pack}\n"
    except Exception:
        ctx_section = ''

    return (
        f"Jesteś agentem `{agent_id}` w wieloagentowym zespole Jarvisa pracującym nad wspólnym projektem `{project_id}`.\n"
        f"Twoja rola: **{role}**\n"
        f"Pozostali członkowie zespołu: {peers_str}\n\n"
        f"## Twoje zadanie w tej fali\n"
        f"{subtask.strip()}\n"
        f"{ctx_section}\n"
        f"## Wspólne środowisko, git worktree i komunikacja na żywo (OBOWIĄZKOWE)\n"
        f"1. Twój bieżący katalog roboczy (`cwd`) to Twój izolowany worktree projektu: `{actual_cwd}` (po zakończeniu Jarvis automatycznie scali Twoje zmiany przez `git merge` do `{pdir / 'repo'}`).\n"
        f"2. Przypisane Ci ścieżki: {owned_str}\n"
        f"3. Zanim zmodyfikujesz plik spoza swojej strefy, zarezerwuj go przez CLI, aby uniknąć konfliktu `git merge`:\n"
        f"   - `jarvis-team locks` — sprawdź kto co edytuje\n"
        f"   - `jarvis-team claim sciezka/do/pliku.py --note \"implementacja API\"`\n"
        f"   - `jarvis-team release --all` — zwolnij blokady po zakończeniu\n"
        f"4. Rozmawiaj i konsultuj się na żywo z innymi agentami przez `jarvis-team`:\n"
        f"   - `jarvis-team chat --last 20` — przeczytaj wiadomości zespołu\n"
        f"   - `jarvis-team say \"Kontrakt API / ustalenie\" --kind chat` — wyślij wiadomość na czat\n"
        f"   - `jarvis-team ask <agent> \"Twoje pytanie\" --wait 90` — zadaj pytanie koledze (lub `owner` do właściciela!)\n"
        f"   - `jarvis-team reply <req_id> \"Odpowiedź\"` — odpowiedz na pytanie kolegi\n"
        f"5. Wypisuj znaczniki postępu `[STAGE] <opis>` na stdout i NIE zadawaj pytań na stdin.\n"
        f"6. Na koniec pracy wyślij krótkie podsumowanie `jarvis-team say \"...\" --kind done`.\n\n"
        f"## Aktualne blokady plików w zespole\n{locks_block}\n\n"
        f"## Wspólna tablica projektu (BOARD.md)\n{board}\n\n"
        f"## Ostatnie wiadomości na czacie zespołu\n{chat_block}\n"
    )


def _default_assignments(meta: dict) -> list[dict]:
    participants = list(meta.get('participants') or [])
    goal = meta.get('goal') or ''
    items = []
    for idx, aid in enumerate(participants):
        role_key, role_desc = DEFAULT_ROLE_ORDER[idx % len(DEFAULT_ROLE_ORDER)]
        items.append({
            'agent': aid,
            'role': role_key,
            'subtask': (
                f"{role_desc}\n"
                f"Cel projektu: {goal}\n"
                f"Uzgodnij interfejsy z kolegami przez `jarvis-team say` / `jarvis-team ask`, "
                f"zarezerwuj swoje pliki przez `jarvis-team claim` i zaimplementuj swoją część."
            ),
            'paths': [],
        })
    return items


def _launch_member_async(project_id: str, assignment: dict, round_no: int,
                         consent: str = 'team', timeout: int | None = None) -> dict:
    pdir = project_root(project_id)
    _ensure_project_layout(pdir)
    aid = str(assignment.get('agent') or '').strip().lower()
    role = str(assignment.get('role') or 'developer').strip()
    subtask = str(assignment.get('subtask') or '').strip()
    paths = [str(p).strip() for p in (assignment.get('paths') or []) if str(p).strip()]

    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        budget = _budget_status(meta)
        if not budget['allowed']:
            raise TeamError(budget['reason'])
        meta['total_runs'] = int(meta.get('total_runs') or 0) + 1
        use_wt = bool(meta.get('use_worktrees'))
        _save_meta(pdir, meta)

    if timeout is None:
        # A member must not be allowed to sit on the wave for its CLI's whole timeout
        # (antigravity defaults to 30 min): one stuck agent then blocks the merge,
        # the gate and the review until the project deadline. Give it at most half
        # the remaining project time.
        remaining = float(budget.get('remaining_seconds') or 0.0)
        if remaining > 0:
            timeout = int(max(300, min(remaining * 0.5, remaining - 120)))
    else:
        # An explicit timeout (the architect pass) still cannot outlive the budget.
        remaining = float(budget.get('remaining_seconds') or 0.0)
        if remaining > 0:
            timeout = int(max(120, min(int(timeout), remaining - 120)))

    if paths:
        claim_files(project_id, aid, paths, note=f'round {round_no} ({role})')

    if use_wt:
        work_dir = prepare_agent_worktree(project_id, aid, round_no)
    else:
        work_dir = pdir / 'repo'

    if use_wt and work_dir != (pdir / 'repo'):
        rw_paths = [work_dir, pdir / 'chat', pdir / 'locks', pdir / 'requests']
        ro_paths = [pdir / 'repo', pdir / 'bin', pdir / 'BOARD.md']
    else:
        rw_paths = [pdir]
        ro_paths = [pdir / 'bin']

    prompt = build_team_prompt(
        project_id,
        agent_id=aid,
        role=role,
        subtask=subtask,
        work_dir=work_dir,
        owned_paths=paths,
        teammates=meta.get('participants') or [],
    )
    extra_env = {
        'JARVIS_TEAM_DIR': str(pdir),
        'JARVIS_TEAM_ID': project_id,
        'JARVIS_TEAM_AGENT': aid,
        'JARVIS_TEAM_ROLE': role,
        'JARVIS_TEAM_BIN': str(pdir / 'bin'),
    }
    label = f"[team:{project_id}/r{round_no}/{role}] {subtask.splitlines()[0][:110]}"

    def _on_done(final_record):
        _handle_member_finished(project_id, aid, role, subtask, paths, round_no, final_record, consent=consent)

    started = agent_cli.start_async(
        aid,
        prompt,
        approved=True,
        timeout=timeout,
        consent=consent,
        cwd=work_dir,
        extra_rw_paths=rw_paths,
        extra_ro_paths=ro_paths,
        extra_env=extra_env,
        raw_prompt=True,
        archive_outbox=False,
        task_label=label,
        on_finish=_on_done,
    )
    _ensure_request_watcher(project_id)
    return {
        'agent': aid,
        'role': role,
        'run_id': started['id'],
        'pid': started['pid'],
        'worktree': str(work_dir),
        'paths': paths,
        'subtask': subtask[:300],
    }


def _pick_fallback_agent(meta: dict, failed_agent: str) -> str:
    active_agents = set((meta.get('active_runs') or {}).keys())
    quarantined = set()
    try:
        import agent_router
        quarantined = set(agent_router.active_circuits().keys())
    except Exception:
        quarantined = set()

    candidates = list(meta.get('participants') or []) + [
        a for a in agent_cli.agent_ids() if a not in (meta.get('participants') or [])
    ]
    for skip_quarantine in (True, False):
        for cand in candidates:
            if cand == failed_agent or cand in active_agents:
                continue
            if skip_quarantine and cand in quarantined:
                continue
            if not agent_cli.binary_present(cand):
                continue
            is_busy, _ = agent_cli._check_running(cand)
            if not is_busy:
                return cand
    return ''


def _parse_architect_plan(pdir: Path, meta: dict) -> list[dict]:
    """Extract structured parallel assignments from PLAN.json written by the Architect."""
    plan_file = pdir / 'repo' / 'PLAN.json'
    if not plan_file.is_file():
        return _default_assignments(meta)
    try:
        raw = json.loads(plan_file.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return _default_assignments(meta)
    if isinstance(raw, dict) and isinstance(raw.get('board'), str) and raw['board'].strip():
        (pdir / 'BOARD.md').write_text(raw['board'].strip() + '\n', encoding='utf-8')
    rows = raw.get('assignments') if isinstance(raw, dict) else (raw if isinstance(raw, list) else None)
    if not isinstance(rows, list) or not rows:
        return _default_assignments(meta)

    known = set(agent_cli.agent_ids())
    seen = set()
    valid = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        aid = str(item.get('agent') or '').strip().lower()
        if aid not in known or aid in seen or not agent_cli.binary_present(aid):
            continue
        seen.add(aid)
        valid.append({
            'agent': aid,
            'role': str(item.get('role') or 'developer').strip()[:40],
            'subtask': str(item.get('subtask') or meta.get('goal') or '').strip(),
            'paths': [_norm_rel_path(p) for p in (item.get('paths') or []) if str(p or '').strip()],
        })
    return valid or _default_assignments(meta)


def _handle_member_finished(project_id: str, agent_id: str, role: str, subtask: str,
                            paths: list[str], round_no: int, final_record: dict,
                            consent: str = 'team') -> None:
    """Merge git worktree, release locks, run deterministic gate, and advance review/fallback/fix waves."""
    pdir = project_root(project_id)
    release_files(project_id, agent_id)

    status = final_record.get('status') or 'failed'
    err_kind = final_record.get('error_kind') or ''
    err_hint = final_record.get('error_hint') or ''

    # A failed run never attempted a merge: record that as None so history does not
    # claim a failed agent had its work merged.
    merge_info = {'merged': None, 'changed_files': [], 'conflicts': []}
    if status == 'done':
        merge_info = merge_agent_worktree(project_id, agent_id, round_no)
        if not merge_info['merged']:
            post_message(
                project_id,
                sender='jarvis',
                kind='system',
                text=(
                    f"[MERGE_CONFLICT] Konflikt scalania zmian `{agent_id}` w plikach: "
                    f"{', '.join(merge_info['conflicts'])} (gałąź `{merge_info.get('branch')}`)."
                ),
                _trigger_wake=False,
            )
        else:
            files_note = f", zmienione pliki: {', '.join(merge_info['changed_files'][:6])}" if merge_info['changed_files'] else ""
            post_message(
                project_id,
                sender=agent_id,
                role=role,
                kind='done',
                text=f"Zakończyłem zadanie w rundzie {round_no} ({final_record.get('seconds')} s{files_note}).",
                _trigger_wake=False,
            )
    else:
        detail = f" [{err_kind}: {err_hint}]" if err_kind else ""
        post_message(
            project_id,
            sender='jarvis',
            kind='system',
            text=f"Agent `{agent_id}` ({role}) zakończył rundę {round_no} ze statusem `{status}`{detail}.",
            _trigger_wake=False,
        )

    fallback_assignment = None
    launch_planned_wave = None
    run_gate_now = False
    after_review_fix = False
    dropped_architect = ''

    with _ORCHESTRATOR_LOCK:
        with _file_lock(pdir / '.meta.lock'):
            meta = _load_meta(pdir)
            active = dict(meta.get('active_runs') or {})
            active.pop(agent_id, None)
            meta['active_runs'] = active
            if merge_info['merged'] is False:
                conflicts = list(meta.get('merge_conflicts') or [])
                conflicts.append({
                    'round': round_no,
                    'agent': agent_id,
                    'branch': merge_info.get('branch', ''),
                    'files': merge_info['conflicts'],
                })
                meta['merge_conflicts'] = conflicts
            hist = list(meta.get('history') or [])
            hist.append({
                'round': round_no,
                'agent': agent_id,
                'role': role,
                'run_id': final_record.get('id'),
                'status': status,
                'error_kind': err_kind,
                'merged': merge_info['merged'],
                'seconds': final_record.get('seconds'),
            })
            meta['history'] = hist[-60:]

            budget = _budget_status(meta)
            phase = meta.get('phase') or 'build'

            if (phase == 'build'
                    and status != 'done'
                    and err_kind in ('quota_exceeded', 'auth_failed', 'model_rejected')
                    and meta.get('auto_fallback', True)
                    and budget['allowed']
                    and not role.startswith('fallback-')):
                replacement = _pick_fallback_agent(meta, agent_id)
                if replacement:
                    fallback_assignment = {
                        'agent': replacement,
                        'role': f'fallback-{role}',
                        'subtask': subtask,
                        'paths': paths,
                    }

            if not active and fallback_assignment is None:
                if phase == 'planning':
                    if budget['allowed']:
                        launch_planned_wave = _parse_architect_plan(pdir, meta)
                        # The architect already had its pass. If it timed out or died,
                        # running it again in the wave only burns the budget (it sat
                        # for 30 min in antigravity's default timeout), so drop its
                        # own assignment and let the rest work.
                        if status != 'done' and launch_planned_wave:
                            kept = [a for a in launch_planned_wave
                                    if str(a.get('agent') or '').strip().lower() != agent_id]
                            if kept and len(kept) != len(launch_planned_wave):
                                launch_planned_wave = kept
                                dropped_architect = agent_id
                    else:
                        meta['phase'] = 'completed'
                        meta['status'] = 'done' if status == 'done' else 'failed'
                elif phase == 'build':
                    run_gate_now = True
                elif phase == 'review':
                    recent = read_messages(project_id, limit=10)
                    verdict_msgs = [
                        m.get('text', '') for m in reversed(recent)
                        if m.get('sender') == agent_id or m.get('kind') in ('review', 'done')
                    ]
                    combined_verdict = '\n'.join(verdict_msgs[:3])
                    if ('[CHANGES_REQUESTED]' in combined_verdict
                            and int(meta.get('current_round') or 1) < int(meta.get('max_rounds') or DEFAULT_MAX_ROUNDS)
                            and budget['allowed']):
                        meta['phase'] = 'build'
                        meta['current_round'] = int(meta.get('current_round') or 1) + 1
                        after_review_fix = True
                    else:
                        meta['phase'] = 'completed'
                        meta['status'] = 'done' if status == 'done' else 'failed'

            _save_meta(pdir, meta)

    if fallback_assignment is not None:
        rep = fallback_assignment['agent']
        post_message(
            project_id,
            sender='jarvis',
            kind='system',
            text=f"Automatyczny fallback po błędzie `{err_kind}`: przekazuję zadanie `{role}` agentowi `{rep}`.",
            _trigger_wake=False,
        )
        try:
            launched = _launch_member_async(project_id, fallback_assignment, round_no, consent=consent)
            with _file_lock(pdir / '.meta.lock'):
                meta = _load_meta(pdir)
                meta.setdefault('active_runs', {})[rep] = launched
                _save_meta(pdir, meta)
            return
        except Exception as exc:
            post_message(project_id, sender='jarvis', kind='system', text=f"Fallback nie powiódł się: {exc}", _trigger_wake=False)

    if launch_planned_wave is not None:
        meta = _load_meta(pdir)
        if dropped_architect:
            post_message(
                project_id,
                sender='jarvis',
                kind='system',
                text=(f"Architekt `{dropped_architect}` zakończył fazę planowania ze statusem "
                      f"`{status}` — nie powtarzam jego zadania w fali, żeby nie blokować zespołu. "
                      f"Pozostali pracują dalej."),
                _trigger_wake=False,
            )
        post_message(
            project_id,
            sender='jarvis',
            kind='plan',
            text=f"Architekt zakończył szkic i plan ({len(launch_planned_wave)} zadań) — startuję równoległy zespół.",
            _trigger_wake=False,
        )
        start_parallel_wave(
            project_id,
            assignments=launch_planned_wave,
            review_agent=meta.get('review_agent') or '',
            auto_fallback=meta.get('auto_fallback', True),
            consent=consent,
            _round_override=1,
        )
        return

    if run_gate_now:
        _evaluate_gate_and_advance(project_id, round_no, consent=consent)
        return

    if after_review_fix:
        meta = _load_meta(pdir)
        next_round = int(meta.get('current_round') or (round_no + 1))
        post_message(
            project_id,
            sender='jarvis',
            kind='system',
            text=f"Recenzent poprosił o poprawki — uruchamiam rundę naprawczą {next_round}.",
            _trigger_wake=False,
        )
        start_parallel_wave(
            project_id,
            assignments=meta.get('assignments') or None,
            review_agent=meta.get('review_agent') or '',
            consent=consent,
            _round_override=next_round,
        )
        return

    _finalize_project_if_completed(project_id)


def _evaluate_gate_and_advance(project_id: str, round_no: int, consent: str = 'team') -> None:
    pdir = project_root(project_id)
    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        if meta.get('phase') not in ('build', 'gate') or int(meta.get('current_round') or 0) != round_no:
            return
        if meta.get('phase') == 'gate':
            return
        meta['phase'] = 'gate'
        _save_meta(pdir, meta)

    round_conflicts = [c for c in (meta.get('merge_conflicts') or []) if c.get('round') == round_no]

    if round_conflicts:
        conflict_files = sorted({f for c in round_conflicts for f in (c.get('files') or [])})
        gate = {
            'round': round_no,
            'ok': False,
            'checks': [{'name': 'git_merge', 'ok': False}],
            'output': f"Konflikty git merge w plikach: {', '.join(conflict_files)}",
        }
    else:
        try:
            gate_res = run_deterministic_gate(project_id)
        except Exception as error:
            # A crash in the gate used to escape into the watcher thread, where it
            # was swallowed: active_runs stayed populated and the project never moved.
            gate_res = {
                'ok': False,
                'checks': [{'name': 'gate_error', 'ok': False}],
                'output': f'Bramka testów nie ukończyła pracy ({type(error).__name__}: {error})'[:800],
            }
        gate = {'round': round_no, **gate_res}

    launch_reviewer = ''
    launch_fix_round = 0

    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        meta['last_gate'] = gate
        budget = _budget_status(meta)
        rev_agent = str(meta.get('review_agent') or '').strip()
        any_ok = (any(h.get('status') == 'done' for h in (meta.get('history') or []) if h.get('round') == round_no)
                  or bool(meta.get('recovered_wave')))

        if not gate['ok']:
            if round_no < int(meta.get('max_rounds') or DEFAULT_MAX_ROUNDS) and budget['allowed'] and any_ok:
                launch_fix_round = round_no + 1
                meta['current_round'] = launch_fix_round
                meta['phase'] = 'build'
            else:
                meta['phase'] = 'completed'
                meta['status'] = 'failed'
        else:
            if rev_agent and agent_cli.binary_present(rev_agent) and budget['allowed'] and any_ok:
                meta['phase'] = 'review'
                launch_reviewer = rev_agent
            else:
                meta['phase'] = 'completed'
                meta['status'] = 'done' if any_ok else 'failed'
        _save_meta(pdir, meta)

    if gate['ok']:
        if gate.get('checks'):
            post_message(
                project_id,
                sender='jarvis',
                kind='system',
                text=f"[GATE_PASSED] Automatyczna bramka testów przeszła pomyślnie ({', '.join(c['name'] for c in gate['checks'])}).",
                _trigger_wake=False,
            )
    else:
        post_message(
            project_id,
            sender='jarvis',
            kind='system',
            text=f"[GATE_FAILED] Bramka testów wykryła błędy przed Code Review:\n{gate.get('output', '')[:1200]}",
            _trigger_wake=False,
        )

    if launch_fix_round:
        meta = _load_meta(pdir)
        start_parallel_wave(
            project_id,
            assignments=meta.get('assignments') or None,
            review_agent=meta.get('review_agent') or '',
            consent=consent,
            _round_override=launch_fix_round,
        )
        return

    if launch_reviewer:
        _start_review_turn(project_id, launch_reviewer, round_no, consent=consent)
        return

    _finalize_project_if_completed(project_id)


def _finalize_project_if_completed(project_id: str) -> None:
    pdir = project_root(project_id)
    meta = _load_meta(pdir)
    if not meta.get('active_runs') and meta.get('phase') == 'completed':
        budget = _budget_status(meta)
        note = budget['reason'] if not budget['allowed'] else ''
        sync_repo_to_outbox(project_id, summary_note=note)
        post_message(
            project_id,
            sender='jarvis',
            kind='system',
            text=f"Praca zespołu zakończona (status: `{meta.get('status')}`). Wyniki wyeksportowano do `outbox/`.",
            _trigger_wake=False,
        )


def _start_review_turn(project_id: str, reviewer_agent: str, round_no: int, consent: str = 'team') -> None:
    pdir = project_root(project_id)
    review_task = (
        "Przeprowadź przegląd integracyjny (Code Review + uruchomienie testów) scalonego kodu w Twoim worktree.\n"
        "1. Przeczytaj `jarvis-team chat --last 30` oraz `BOARD.md`.\n"
        "2. Sprawdź spójność importów, kontraktów między modułami i uruchom testy.\n"
        "3. Drobne usterki możesz poprawić bezpośrednio w swoim katalogu roboczym (zostaną scalone).\n"
        "4. Jeśli wszystko działa i spełnia cel projektu, wyślij na czat: `jarvis-team say \"[APPROVED] Kod przetestowany i spójny.\" --kind review`.\n"
        "5. Jeśli wymagane są poprawki od autorów, wyślij konkretne uwagi z tagiem `[CHANGES_REQUESTED]` przez `jarvis-team say \"[CHANGES_REQUESTED] ...\" --kind review`."
    )
    post_message(
        project_id,
        sender='jarvis',
        kind='system',
        text=f"Fala implementacji przeszła bramkę testów — uruchamiam przegląd integracyjny przez `{reviewer_agent}`.",
        _trigger_wake=False,
    )
    try:
        launched = _launch_member_async(
            project_id,
            {'agent': reviewer_agent, 'role': 'reviewer', 'subtask': review_task, 'paths': []},
            round_no,
            consent=consent,
        )
        with _file_lock(pdir / '.meta.lock'):
            meta = _load_meta(pdir)
            done_ids = {h.get('run_id') for h in (meta.get('history') or [])}
            if launched['run_id'] not in done_ids:
                meta.setdefault('active_runs', {})[reviewer_agent] = launched
            _save_meta(pdir, meta)
    except Exception as exc:
        with _file_lock(pdir / '.meta.lock'):
            meta = _load_meta(pdir)
            meta['phase'] = 'completed'
            meta['status'] = 'done'
            _save_meta(pdir, meta)
        sync_repo_to_outbox(project_id, summary_note=f'Pominięto review ({exc}).')


def start_architect_phase(project_id: str, architect_agent: str = '',
                          review_agent: str = '', auto_fallback: bool = True,
                          approved: bool = True, consent: str = 'team',
                          timeout: int | None = None) -> dict:
    """Run an initial Architect pass to scaffold files and generate PLAN.json before the parallel swarm."""
    if approved is not True:
        raise TeamError('Explicit approval is required.')
    pdir = project_root(project_id)
    _ensure_project_layout(pdir)

    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        participants = list(meta.get('participants') or [])
        arch = str(architect_agent or (participants[0] if participants else '')).strip().lower()
        agent_cli._agent(arch)
        if not agent_cli.binary_present(arch):
            raise TeamError(f'Architect agent {arch!r} is not installed on PATH.')
        meta['status'] = 'running'
        meta['phase'] = 'planning'
        meta['auto_fallback'] = bool(auto_fallback)
        if review_agent:
            agent_cli._agent(review_agent)
            meta['review_agent'] = review_agent
        _save_meta(pdir, meta)

    peers = ', '.join(participants)
    arch_subtask = (
        f"Zaprojektuj architekturę i szkielet projektu dla zespołu ({peers}).\n"
        f"Cel główny: {meta.get('goal')}\n\n"
        f"1. Utwórz w bieżącym katalogu bazowe pliki interfejsów/szkieletu (zostaną scalone do `repo/`).\n"
        f"2. Zapisz plik `PLAN.json` w formacie:\n"
        f'   `{{"board": "# Plan...", "assignments": [{{"agent": "claude", "role": "backend", "subtask": "...", "paths": ["api/"]}}]}}`\n'
        f"   rozdzielając niepokrywające się ścieżki pomiędzy dostępnych uczestników ({peers}).\n"
        f"3. Ogłoś główne kontrakty na czacie przez `jarvis-team say \"...\" --kind plan`."
    )
    post_message(
        project_id,
        sender='jarvis',
        kind='plan',
        text=f"Faza Architekta: `{arch}` przygotowuje szkielet projektu i podział ról `PLAN.json`.",
        _trigger_wake=False,
    )
    info = _launch_member_async(
        project_id,
        {'agent': arch, 'role': 'architect', 'subtask': arch_subtask, 'paths': []},
        0,
        consent=consent,
        # agy (antigravity) needs minutes to scaffold and write PLAN.json; 240 s cut
        # it off mid-plan and the wave then ran twice.
        timeout=min(int(timeout or 420), 900),
    )
    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        done_ids = {h.get('run_id') for h in (meta.get('history') or [])}
        if info['run_id'] not in done_ids:
            meta.setdefault('active_runs', {})[arch] = info
        _save_meta(pdir, meta)
    return {'ok': True, 'project_id': project_id, 'phase': 'planning', 'launched': [info], 'status': project_status(project_id)}


def start_parallel_wave(project_id: str, assignments: list[dict] | None = None,
                        review_agent: str = '', auto_fallback: bool = True,
                        approved: bool = True, consent: str = 'team',
                        timeout: int | None = None, _round_override: int | None = None) -> dict:
    """Launch multiple agents in parallel on isolated git worktrees with live chat and file locks."""
    if approved is not True:
        raise TeamError('Explicit approval is required to start a team wave.')
    pdir = project_root(project_id)
    _ensure_project_layout(pdir)

    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        budget = _budget_status(meta)
        if not budget['allowed']:
            raise TeamError(budget['reason'])
        if meta.get('active_runs'):
            still_alive = {}
            for aid, info in list((meta.get('active_runs') or {}).items()):
                alive, _ = agent_cli._check_running(aid)
                if alive:
                    still_alive[aid] = info
                else:
                    release_files(project_id, aid)
            meta['active_runs'] = still_alive
            if still_alive:
                _save_meta(pdir, meta)
                raise TeamError(f"Team wave already active for agents: {', '.join(still_alive)}")

        plan = list(assignments) if assignments else (meta.get('assignments') or _default_assignments(meta))
        if not plan:
            raise TeamError('No agent assignments available to launch.')

        seen_agents = set()
        validated_plan = []
        for item in plan:
            if not isinstance(item, dict):
                raise TeamError('Each assignment must be an object.')
            aid = str(item.get('agent') or '').strip().lower()
            agent_cli._agent(aid)
            if aid in seen_agents:
                raise TeamError(f'Agent {aid!r} appears twice in the same parallel wave; each agent runs once per wave.')
            if not agent_cli.binary_present(aid):
                raise TeamError(f'Agent {aid!r} is not installed on PATH.')
            seen_agents.add(aid)
            subtask_txt = str(item.get('subtask') or meta.get('goal') or '').strip()
            last_gate = meta.get('last_gate')
            if _round_override and _round_override > 1 and isinstance(last_gate, dict) and not last_gate.get('ok'):
                subtask_txt += f"\n\nUWAGA — Napraw błędy wykryte w poprzedniej rundzie:\n{last_gate.get('output', '')[:1000]}"
            validated_plan.append({
                'agent': aid,
                'role': str(item.get('role') or 'developer').strip()[:40],
                'subtask': subtask_txt,
                'paths': [_norm_rel_path(p) for p in (item.get('paths') or []) if str(p or '').strip()],
            })

        round_no = _round_override if _round_override is not None else (int(meta.get('current_round') or 0) + 1)
        meta['current_round'] = round_no
        meta['status'] = 'running'
        meta['phase'] = 'build'
        meta['assignments'] = validated_plan
        meta['auto_fallback'] = bool(auto_fallback)
        if review_agent:
            agent_cli._agent(review_agent)
            meta['review_agent'] = review_agent
        for aid in seen_agents:
            if aid not in meta['participants']:
                meta['participants'].append(aid)
        _save_meta(pdir, meta)

    summary_roles = ', '.join(f"{x['agent']} ({x['role']})" for x in validated_plan)
    post_message(
        project_id,
        sender='jarvis',
        kind='plan',
        text=f"Start równoległej fali #{round_no}: {summary_roles}.",
        _trigger_wake=False,
    )

    with _ORCHESTRATOR_LOCK:
        launched = {}
        errors = []
        for item in validated_plan:
            try:
                info = _launch_member_async(project_id, item, round_no, consent=consent, timeout=timeout)
                launched[item['agent']] = info
            except Exception as exc:
                release_files(project_id, item['agent'])
                errors.append({'agent': item['agent'], 'error': str(exc)})

        with _file_lock(pdir / '.meta.lock'):
            meta = _load_meta(pdir)
            done_ids = {
                h.get('run_id') for h in (meta.get('history') or [])
                if h.get('round') == round_no
            }
            active_now = dict(meta.get('active_runs') or {})
            for aid, info in launched.items():
                if info['run_id'] not in done_ids:
                    active_now[aid] = info
            meta['active_runs'] = active_now
            if not active_now and not launched:
                meta['status'] = 'failed'
                meta['phase'] = 'idle'
            _save_meta(pdir, meta)

    return {
        'ok': bool(launched),
        'project_id': project_id,
        'round': round_no,
        'launched': list(launched.values()),
        'errors': errors,
        'status': project_status(project_id),
    }


def start_team_project(goal: str, participants=None, assignments: list[dict] | None = None,
                       title: str = '', project_id: str = '', review_agent: str = '',
                       architect_agent: str = '', plan_first: bool = False,
                       max_rounds: int = DEFAULT_MAX_ROUNDS,
                       max_total_runs: int = DEFAULT_MAX_TOTAL_RUNS,
                       max_project_minutes: int = DEFAULT_MAX_PROJECT_MINUTES,
                       use_worktrees: bool = True, seed_dir: str = '',
                       auto_fallback: bool = True, approved: bool = True,
                       consent: str = 'team', timeout: int | None = None) -> dict:
    """Create a shared project room and launch either Architect -> Swarm or direct Parallel Swarm."""
    if approved is not True:
        raise TeamError('Explicit approval is required to start a team project.')
    if assignments and not participants:
        participants = [str(a.get('agent') or '').strip().lower() for a in assignments if isinstance(a, dict)]
    mode = 'plan_then_parallel' if (plan_first or architect_agent) and not assignments else 'parallel'
    created = create_project(
        goal=goal,
        participants=participants,
        title=title,
        project_id=project_id,
        mode=mode,
        max_rounds=max_rounds,
        max_total_runs=max_total_runs,
        max_project_minutes=max_project_minutes,
        use_worktrees=use_worktrees,
        seed_dir=seed_dir,
    )
    pid = created['id']
    if mode == 'plan_then_parallel':
        return start_architect_phase(
            pid,
            architect_agent=architect_agent,
            review_agent=review_agent,
            auto_fallback=auto_fallback,
            approved=approved,
            consent=consent,
            timeout=timeout,
        )
    return start_parallel_wave(
        pid,
        assignments=assignments,
        review_agent=review_agent,
        auto_fallback=auto_fallback,
        approved=approved,
        consent=consent,
        timeout=timeout,
    )


def nudge_agent(project_id: str, agent_id: str, message: str, role: str = 'collaborator',
                paths: list[str] | None = None, approved: bool = True,
                consent: str = 'team', timeout: int | None = None) -> dict:
    """Post a message to the team chat and wake a single idle agent on the shared project."""
    if approved is not True:
        raise TeamError('Explicit approval is required.')
    pdir = project_root(project_id)
    meta = _load_meta(pdir)
    post_message(project_id, sender='owner', to=agent_id, kind='question', text=message, _trigger_wake=False)
    round_no = max(1, int(meta.get('current_round') or 1))
    item = {
        'agent': agent_id,
        'role': role,
        'subtask': message,
        'paths': paths or [],
    }
    info = _launch_member_async(project_id, item, round_no, consent=consent, timeout=timeout)
    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        meta['status'] = 'running'
        meta['phase'] = 'build'
        if agent_id not in meta['participants']:
            meta['participants'].append(agent_id)
        done_ids = {h.get('run_id') for h in (meta.get('history') or [])}
        if info['run_id'] not in done_ids:
            meta.setdefault('active_runs', {})[agent_id] = info
        _save_meta(pdir, meta)
    return {'ok': True, 'project_id': project_id, 'launched': info}


def stop_project(project_id: str) -> dict:
    """Stop all active member runs in a team project and release their file locks."""
    pdir = project_root(project_id)
    with _file_lock(pdir / '.meta.lock'):
        meta = _load_meta(pdir)
        active = dict(meta.get('active_runs') or {})
        meta['active_runs'] = {}
        meta['status'] = 'stopped'
        meta['phase'] = 'stopped'
        _save_meta(pdir, meta)

    stopped = []
    for aid in set(list(active.keys()) + list(meta.get('participants') or [])):
        release_files(project_id, aid)
        if aid in active:
            res = agent_cli.stop(aid)
            stopped.append({'agent': aid, **res})
    post_message(project_id, sender='jarvis', kind='system', text='Zatrzymano aktywną falę zespołu.', _trigger_wake=False)
    return {'ok': True, 'project_id': project_id, 'stopped': stopped}


def project_status(project_id: str) -> dict:
    """Full live telemetry for a collaborative project: members' live_progress, chat, locks, gate, and budget."""
    pdir = project_root(project_id)
    meta = _load_meta(pdir)
    participants = list(meta.get('participants') or [])
    if meta.get('active_runs'):
        # A Jarvis restart leaves the wave looking active forever; this clears the
        # dead members, merges their branches and lets the gate decide.
        _maybe_reconcile(project_id)

    members = {}
    any_running = False
    for aid in participants:
        try:
            prog = agent_cli.live_progress(aid)
        except Exception:
            prog = {'agent': aid, 'running': False, 'status': 'idle'}
        in_this_team = aid in (meta.get('active_runs') or {})
        if in_this_team and prog.get('running'):
            any_running = True
        members[aid] = {
            'in_active_wave': in_this_team,
            'progress': prog,
        }

    status = 'running' if any_running else meta.get('status', 'ready')
    board_path = pdir / 'BOARD.md'
    board_text = board_path.read_text(encoding='utf-8', errors='replace')[:6000] if board_path.is_file() else ''

    return {
        'id': meta['id'],
        'title': meta.get('title', ''),
        'goal': meta.get('goal', ''),
        'mode': meta.get('mode', 'parallel'),
        'use_worktrees': bool(meta.get('use_worktrees')),
        'status': status,
        'phase': meta.get('phase', 'idle'),
        'current_round': meta.get('current_round', 0),
        'max_rounds': meta.get('max_rounds', DEFAULT_MAX_ROUNDS),
        'budget': _budget_status(meta),
        'last_gate': meta.get('last_gate'),
        'merge_conflicts': meta.get('merge_conflicts') or [],
        'participants': participants,
        'review_agent': meta.get('review_agent', ''),
        'active_runs': meta.get('active_runs') or {},
        'members': members,
        'locks': active_claims(project_id),
        'messages': read_messages(project_id, limit=30),
        'repo_files': repo_files(project_id, subdir='repo'),
        'outbox_files': repo_files(project_id, subdir='outbox'),
        'board': board_text,
        'history': (meta.get('history') or [])[-25:],
        'project_dir': str(pdir),
    }


def active_waves(limit: int = 40) -> list[dict]:
    """Projects with at least one member run in flight (cheap: reads project.json only).

    Used by the hot-reload watcher: restarting Jarvis mid-wave kills the bwrap
    sandboxes and turns finished work into `failed` runs.
    """
    base = agent_cli.projects_root()
    if not base.is_dir():
        return []
    waves = []
    try:
        entries = sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[:max(1, limit)]
    except OSError:
        return []
    for sub in entries:
        meta_path = sub / 'project.json'
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        active = meta.get('active_runs') or {}
        if active:
            waves.append({'id': meta.get('id') or sub.name,
                          'title': meta.get('title', ''),
                          'agents': sorted(active.keys())})
    return waves


def list_projects(limit: int = 30) -> list[dict]:
    """Summary of collaborative projects sorted newest-first."""
    base = agent_cli.projects_root()
    if not base.is_dir():
        return []
    rows = []
    for sub in base.iterdir():
        if not sub.is_dir() or not (sub / 'project.json').is_file():
            continue
        try:
            meta = _load_meta(sub)
        except TeamError:
            continue
        rows.append({
            'id': meta.get('id', sub.name),
            'title': meta.get('title', ''),
            'status': meta.get('status', 'ready'),
            'phase': meta.get('phase', 'idle'),
            'mode': meta.get('mode', 'parallel'),
            'use_worktrees': bool(meta.get('use_worktrees')),
            'participants': meta.get('participants') or [],
            'current_round': meta.get('current_round', 0),
            'total_runs': meta.get('total_runs', 0),
            'max_total_runs': meta.get('max_total_runs', DEFAULT_MAX_TOTAL_RUNS),
            'active_count': len(meta.get('active_runs') or {}),
            'updated_at': meta.get('updated_at', 0),
        })
    rows.sort(key=lambda r: float(r.get('updated_at') or 0), reverse=True)
    return rows[:max(1, min(int(limit or 30), 100))]
