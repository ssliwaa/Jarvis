"""Opt-in Telegram channel. Remote Operator jobs always use local approvals."""
import json
import os
import re
import sqlite3
import threading
import urllib.request
from contextlib import contextmanager
from pathlib import Path


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class TelegramTransport:
    def __init__(self, token, opener=None):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{1,128}", token):
            raise ValueError("Invalid Telegram bot credential")
        self._url = "https://api.telegram.org/bot" + token + "/"
        self._opener = opener or urllib.request.build_opener(_NoRedirect())

    def _call(self, method, data):
        request = urllib.request.Request(self._url + method,
            data=json.dumps(data).encode("utf-8"), headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=15) as response:
                payload = json.loads(response.read(1024 * 1024))
            if not isinstance(payload, dict) or payload.get("ok") is not True:
                raise ValueError("Telegram request failed")
            return payload.get("result")
        except Exception:
            # Never propagate URLs or upstream response bodies containing credentials.
            raise RuntimeError("Telegram request failed") from None

    def poll(self, offset):
        result = self._call("getUpdates", {"offset": offset, "timeout": 10,
                                           "allowed_updates": ["message"]})
        if not isinstance(result, list):
            raise RuntimeError("Telegram request failed")
        return result

    def send(self, chat_id, text, reply_markup=None):
        payload = {"chat_id": chat_id, "text": str(text)[:4000]}
        if isinstance(reply_markup, dict):
            payload["reply_markup"] = reply_markup
        self._call("sendMessage", payload)

    def answer_callback(self, callback_id, text=""):
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = str(text)[:180]
        self._call("answerCallbackQuery", payload)


class TelegramChannel:
    def __init__(self, agent, transport, owner_id, state_root, default_target=None):
        if type(owner_id) is not int or owner_id <= 0:
            raise ValueError("A positive owner user ID is required")
        self.agent = agent
        self.transport = transport
        self.owner_id = owner_id
        self.default_target = str(default_target or Path(__file__).resolve().parent)
        self._stop = threading.Event()
        self._thread = None
        root = Path(state_root) / "telegram"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.db_path = root / "channel.db"
        fd = os.open(self.db_path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db_path.chmod(0o600)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS updates (id INTEGER PRIMARY KEY, job_id TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS notices (job_id TEXT PRIMARY KEY, state TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def start(self):
        if self._thread is not None:
            raise RuntimeError("Telegram channel already started")
        self._thread = threading.Thread(target=self._run, name="jarvis-telegram", daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                # Retry silently; exception text may contain credentials.
                self._stop.wait(5)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=16)

    def poll_once(self):
        with self._connect() as db:
            row = db.execute("SELECT value FROM meta WHERE key='offset'").fetchone()
        offset = row[0] if row else -1
        updates = self.transport.poll(offset)
        if self._stop.is_set():
            return
        valid = sorted((item for item in updates if isinstance(item, dict)
                        and type(item.get("update_id")) is int and item["update_id"] >= 0),
                       key=lambda item: item["update_id"])
        if row is None:
            # Opt-in never executes messages that predate initial activation.
            next_offset = valid[-1]["update_id"] + 1 if valid else 0
            with self._connect() as db:
                db.execute("INSERT INTO meta(key, value) VALUES ('offset', ?)", (next_offset,))
            return
        for update in valid:
            if self._stop.is_set():
                return
            if update["update_id"] < offset:
                continue
            self.handle_update(update)
            offset = update["update_id"] + 1
            with self._connect() as db:
                db.execute("UPDATE meta SET value=? WHERE key='offset'", (offset,))
        self.notify_jobs()

    def notify_jobs(self):
        with self._connect() as db:
            jobs = db.execute("SELECT job_id FROM updates WHERE job_id IS NOT NULL").fetchall()
        for (job_id,) in jobs:
            try:
                snapshot = self.agent.status(job_id).get("job") or {}
                state = snapshot.get("status")
                if state not in ("awaiting_approval", "done", "error", "stopped"):
                    continue
                with self._connect() as db:
                    prior = db.execute("SELECT state FROM notices WHERE job_id=?", (job_id,)).fetchone()
                    if prior and prior[0] == state:
                        continue
                suffix = " Review locally; no remote approval is supported." if state == "awaiting_approval" else " Inspect details locally."
                # Record the notice only after delivery, so a transport error is retried
                # on the next poll instead of being silently marked as sent.
                self.transport.send(self.owner_id, f"Job {job_id}: {state}.{suffix}")
                with self._connect() as db:
                    db.execute("INSERT OR REPLACE INTO notices(job_id, state) VALUES (?, ?)", (job_id, state))
            except Exception:
                continue

    def _send_safe(self, text, reply_markup=None):
        if reply_markup is not None:
            try:
                self.transport.send(self.owner_id, text, reply_markup=reply_markup)
                return
            except TypeError:
                pass
        self.transport.send(self.owner_id, text)

    def _claim_update(self, update_id: int) -> bool:
        with self._connect() as db:
            try:
                db.execute("INSERT INTO updates(id) VALUES (?)", (update_id,))
                return True
            except sqlite3.IntegrityError:
                return False

    def _dispatch_mobile_command(self, cmd: str, arg: str) -> None:
        if cmd == "/team":
            import agent_team
            if arg:
                res = agent_team.start_team_project(goal=arg, plan_first=True, approved=True, consent="telegram-owner")
                pid = res.get("project_id", "")
                kb = {"inline_keyboard": [[
                    {"text": "Status", "callback_data": f"status:{pid}"},
                    {"text": "Diff", "callback_data": f"diff:team:{pid}"},
                ]]}
                self._send_safe(f"Zespół wystartował: {pid} (faza: {res.get('phase', 'build')}).", reply_markup=kb)
                return
            projects = agent_team.list_projects(5)
            if not projects:
                self._send_safe("Brak projektów zespołowych. Użyj /team <cel>, aby uruchomić zespół.")
                return
            lines = ["Ostatnie projekty zespołowe:"]
            buttons = []
            for p in projects:
                pid = p["id"]
                lines.append(f"- {pid}: {p['status']} (r{p['current_round']}, uruchomienia {p.get('total_runs', 0)})")
                buttons.append([
                    {"text": f"Diff {pid[:14]}", "callback_data": f"diff:team:{pid}"},
                    {"text": f"Wdróż {pid[:14]}", "callback_data": f"apply:team:{pid}"},
                ])
            self._send_safe("\n".join(lines), reply_markup={"inline_keyboard": buttons[:4]})
            return

        if cmd == "/diff":
            import agent_review
            src = arg if ":" in arg or arg in ("claude", "hermes", "opencode", "antigravity") else f"team:{arg}"
            diff = agent_review.diff_outbox(src, self.default_target)
            changed = [f for f in (diff.get("files") or []) if f.get("status") in ("changed", "new")]
            if not changed:
                self._send_safe(f"Brak zmian do wdrożenia w {src}.")
                return
            summary = [f"Diff {src} -> {len(changed)} plików:"]
            for row in changed[:8]:
                summary.append(f"- [{row['status']}] {row['path']}")
            kb = {"inline_keyboard": [[{"text": f"Wdróż {src}", "callback_data": f"apply:{src}"}]]}
            self._send_safe("\n".join(summary), reply_markup=kb)
            return

        if cmd == "/apply":
            import agent_review
            src = arg if ":" in arg or arg in ("claude", "hermes", "opencode", "antigravity") else f"team:{arg}"
            applied = agent_review.apply_outbox(src, self.default_target)
            kb = {"inline_keyboard": [[{"text": "Cofnij Checkpoint", "callback_data": "rollback:"}]]}
            self._send_safe(
                f"Wdrożono {applied.get('applied', 0)} plików z {src} (checkpoint: {applied.get('checkpoint_created')}).",
                reply_markup=kb,
            )
            return

        if cmd == "/rollback":
            import agent_review
            restored = agent_review.rollback_last_checkpoint(self.default_target, commit_hash=arg)
            self._send_safe(f"Cofnięto katalog do checkpointu {str(restored.get('restored_to', ''))[:10]}.")
            return

        if cmd == "/watchdog":
            import health_watchdog
            res = health_watchdog.scan_logs(auto_repair=(arg.strip().lower() == "repair"), project_root=self.default_target)
            incs = res.get("incidents") or []
            if not incs:
                self._send_safe("Watchdog: brak powtarzających się wyjątków w logach usługi.")
                return
            lines = [f"Watchdog wykrył {len(incs)} incydent(ów):"]
            for inc in incs[:5]:
                lines.append(f"- [{inc['signature']}] {inc['error_type']} ({inc['count']}x w {Path(inc['file']).name}:{inc['line']})")
            self._send_safe("\n".join(lines))
            return

        if cmd == "/reply":
            import voice_bridge
            if not arg:
                pending = voice_bridge.pending_owner_questions()
                if not pending:
                    self._send_safe("Brak oczekujących pytań od agentów.")
                else:
                    q = pending[0]
                    self._send_safe(f"Pytanie [{q['id']}] od {q['from']}: {q['question']}\nOdpowiedz: /reply Twoja odpowiedź")
                return
            answered = voice_bridge.answer_owner_question(arg, source="telegram")
            self._send_safe(f"Przekazano odpowiedź do {answered.get('from')} (pytanie {answered.get('id')}).")
            return

    def handle_update(self, update):
        if not isinstance(update, dict) or type(update.get("update_id")) is not int:
            return
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            cb_sender = callback.get("from")
            cb_msg = callback.get("message") or {}
            cb_chat = cb_msg.get("chat") if isinstance(cb_msg, dict) else None
            data = str(callback.get("data") or "")
            if (isinstance(cb_sender, dict) and type(cb_sender.get("id")) is int
                    and cb_sender["id"] == self.owner_id and cb_sender.get("is_bot") is not True
                    and isinstance(cb_chat, dict) and cb_chat.get("id") == self.owner_id
                    and cb_chat.get("type") == "private" and data):
                if not self._claim_update(update["update_id"]):
                    return
                try:
                    if hasattr(self.transport, "answer_callback") and callback.get("id"):
                        self.transport.answer_callback(callback["id"])
                    if data.startswith("diff:"):
                        self._dispatch_mobile_command("/diff", data[5:])
                    elif data.startswith("apply:"):
                        self._dispatch_mobile_command("/apply", data[6:])
                    elif data.startswith("rollback:"):
                        self._dispatch_mobile_command("/rollback", data[9:])
                    elif data.startswith("status:"):
                        import agent_team
                        st = agent_team.project_status(data[7:])
                        self._send_safe(f"Projekt {st['id']}: {st['status']} ({st['phase']}, runda {st['current_round']}).")
                except Exception:
                    return
            return

        message = update.get("message")
        if not isinstance(message, dict):
            return
        sender, chat = message.get("from"), message.get("chat")
        if not isinstance(sender, dict) or not isinstance(chat, dict):
            return
        if (type(sender.get("id")) is not int or sender["id"] != self.owner_id
                or sender.get("is_bot") is True or type(chat.get("id")) is not int
                or chat["id"] != self.owner_id or chat.get("type") != "private"
                or message.get("forward_origin") or message.get("forward_date")
                or message.get("via_bot")):
            return
        text = message.get("text")
        if not isinstance(text, str):
            return
        stripped = text.strip()
        parts = stripped.split(None, 1)
        cmd = parts[0].lower() if parts else ""
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/team", "/diff", "/apply", "/rollback", "/watchdog", "/reply"):
            if len(arg) > 4000 or not self._claim_update(update["update_id"]):
                return
            try:
                self._dispatch_mobile_command(cmd, arg)
            except Exception:
                return
            return

        if not text.startswith("/run "):
            return
        task = text[5:].strip()
        if not task or len(task) > 4000:
            return
        # Claim before launching: a crash may lose a request, but must not run it twice.
        if not self._claim_update(update["update_id"]):
            return
        try:
            job = self.agent.start(task, queue=True, remote=True)
            job_id = job.get("id")
            if not isinstance(job_id, str) or not job_id.isalnum() or len(job_id) > 64:
                return
            with self._connect() as db:
                db.execute("UPDATE updates SET job_id=? WHERE id=?", (job_id, update["update_id"]))
            self.transport.send(self.owner_id, f"Job {job_id}: {job.get('status', 'started')}. Local approval required for tools.")
        except Exception:
            # Never include exception details: transport errors can contain a bot token.
            return


def _bot_token():
    """Prefer the environment, then the local credential store.

    Keeping the token in the keyring means the systemd unit only carries the
    enable flag and the owner id, so a unit file or `systemctl cat` never shows
    a working bot credential.
    """
    token = os.environ.get("JARVIS_TELEGRAM_BOT_TOKEN", "").strip()
    if token:
        return token
    try:
        from operator_tools import SecretStore, ToolError
        item = SecretStore().get("telegram-bot-token")
    except (ImportError, ToolError):
        return ""
    return str(item.get("value") or "").strip()


def from_environment(agent, state_root):
    if os.environ.get("JARVIS_TELEGRAM_ENABLED") != "1":
        return None
    if agent is None:
        raise ValueError("Telegram requires an enabled Operator")
    owner = os.environ.get("JARVIS_TELEGRAM_OWNER_ID", "")
    if not re.fullmatch(r"[1-9][0-9]{0,18}", owner):
        raise ValueError("Telegram owner ID is required")
    token = _bot_token()
    if not token:
        raise ValueError("A Telegram bot token is required (environment or stored credential)")
    transport = TelegramTransport(token)
    return TelegramChannel(agent, transport, int(owner), state_root)
