"""Persistent recurring Operator tasks.

The scheduler reuses AgentService's single-job lock, so a scheduled task can
never run two browsers at once. Jobs are persisted; a retry uses a bounded
backoff and records the real terminal status when the Operator reports one.
"""
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from atomic_io import atomic_write_json

TOOLS = Path.home() / ".jarvis-tools"
SCHEDULES_PATH = TOOLS / "schedules.json"
MAX_RETRIES = 3
DEFAULT_JOB_TIMEOUT = 1800


def _job_timeout():
    """How long a scheduled run may hold the scheduler while it is observed.

    Operator jobs include approvals and multi-step browsing, so the old
    three-minute budget marked healthy long jobs as timeouts and retried them.
    The wait is bounded and interruptible by stop(); a timeout is still
    reported, never mistaken for success.
    """
    try:
        value = int(os.environ.get("JARVIS_SCHEDULE_JOB_TIMEOUT", DEFAULT_JOB_TIMEOUT))
    except (TypeError, ValueError):
        value = DEFAULT_JOB_TIMEOUT
    return max(30, min(value, 24 * 3600))


class ScheduleError(Exception):
    pass


class Scheduler:
    def __init__(self, service, path: Path = SCHEDULES_PATH):
        self.service = service
        self.path = Path(path)
        self.lock = threading.RLock()
        self.items = []
        self._stop = threading.Event()
        self._thread = None
        self._run_lock = threading.Lock()
        self.job_timeout = _job_timeout()
        self._heartbeat_checked = 0.0
        self._load()

    def _load(self):
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                raise ValueError
        except (OSError, ValueError, UnicodeError):
            payload = []
        self.items = [item for item in payload if isinstance(item, dict) and item.get("id")]
        for item in self.items:
            item.setdefault("enabled", True)
            item.setdefault("max_retries", 1)
            item.setdefault("retry_count", 0)
            item.setdefault("last_error", "")

    def _save(self):
        atomic_write_json(self.path, self.items, indent=2, ensure_ascii=True, mode=0o600, dir_mode=0o755)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="jarvis-schedules", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def list(self):
        with self.lock:
            return [dict(item) for item in self.items]

    def add(self, task, every_seconds=3600, name=None, max_retries=1):
        task = str(task or "").strip()
        if not 1 <= len(task) <= 4000:
            raise ScheduleError("A scheduled task must be between 1 and 4,000 characters.")
        try:
            every = int(every_seconds)
        except (TypeError, ValueError):
            raise ScheduleError("The interval must be an integer number of seconds.") from None
        if not 60 <= every <= 30 * 24 * 3600:
            raise ScheduleError("The interval must be between 60 seconds and 30 days.")
        try:
            retries = max(0, min(int(max_retries), MAX_RETRIES))
        except (TypeError, ValueError):
            retries = 1
        label = str(name or task[:48]).strip()[:80] or "Scheduled task"
        item = {"id": uuid.uuid4().hex[:12], "name": label, "task": task,
                "every_seconds": every, "next_at": time.time() + every,
                "enabled": True, "last_run": None, "last_status": None,
                "last_error": "", "retry_count": 0, "max_retries": retries,
                "runs": 0, "last_job_id": None}
        with self.lock:
            self.items.append(item)
            self._save()
        return dict(item)

    def remove(self, item_id):
        with self.lock:
            before = len(self.items)
            self.items = [item for item in self.items if item.get("id") != item_id]
            if len(self.items) == before:
                raise ScheduleError("That scheduled task does not exist.")
            self._save()
        return {"ok": True, "removed": item_id}

    def set_enabled(self, item_id, enabled):
        with self.lock:
            item = next((row for row in self.items if row.get("id") == item_id), None)
            if item is None:
                raise ScheduleError("That scheduled task does not exist.")
            item["enabled"] = bool(enabled)
            item["next_at"] = time.time() + int(item.get("every_seconds") or 3600)
            self._save()
            return dict(item)

    def run_now(self, item_id):
        """Queue an existing schedule immediately without changing its cadence."""
        with self.lock:
            item = next((row for row in self.items if row.get("id") == item_id), None)
            if item is None:
                raise ScheduleError("That scheduled task does not exist.")
            snapshot = dict(item)
        if not self._run_lock.acquire(blocking=False):
            raise ScheduleError("A scheduled task is already running.")
        thread = threading.Thread(target=self._run_owned, args=(snapshot, True),
                                  name=f"jarvis-schedule-now-{item_id}", daemon=True)
        try:
            thread.start()
        except Exception:
            self._run_lock.release()
            raise
        return {"ok": True, "queued": item_id}

    def _run_owned(self, item, manual=False):
        """Run a job whose run lock the caller already holds, then release it."""
        try:
            self._run_item(item, manual=manual)
        except Exception as error:
            self._notify("Jarvis scheduler", f"{type(error).__name__}: {error}")
        finally:
            self._run_lock.release()

    def _run_guarded(self, item):
        # A manual run can hold the lock for a long time; stop() must still be
        # able to end the scheduler thread promptly instead of blocking on it.
        while not self._stop.is_set():
            if self._run_lock.acquire(timeout=0.5):
                break
        else:
            return
        try:
            self._run_item(item)
        except Exception as error:
            self._notify("Jarvis scheduler", f"{type(error).__name__}: {error}")
        finally:
            self._run_lock.release()

    def _notify(self, title, body):
        if not shutil.which("notify-send"):
            return
        try:
            subprocess.run(["notify-send", "-a", "Jarvis", title, body], timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _terminal_from_history(self, job_id):
        """Find a completed job after the service has already cleared `job`."""
        history = getattr(self.service, "history_rows", None)
        if not callable(history):
            return None
        try:
            rows = history()
        except Exception:
            return None
        for row in reversed(rows or []):
            if isinstance(row, dict) and row.get("id") == job_id \
                    and row.get("status") in ("done", "error", "stopped"):
                return str(row["status"]), str(row.get("error") or "")
        return None

    def _wait_for_job(self, started, timeout=None):
        """Read the real terminal state when the service exposes a job snapshot."""
        job = started if isinstance(started, dict) else {}
        job_id = job.get("id")
        if not job_id or not hasattr(self.service, "status"):
            return job_id, "started", ""
        timeout = self.job_timeout if timeout is None else timeout
        deadline = time.time() + timeout
        problem = ""
        while time.time() < deadline and not self._stop.is_set():
            try:
                snapshot = self.service.status(job_id)
            except Exception as error:
                # A finished job may already be gone from the active slot; its
                # terminal state lives in the persisted history.
                terminal = self._terminal_from_history(job_id)
                if terminal is not None:
                    return job_id, *terminal
                problem = f"status: {type(error).__name__}"
                break
            last = snapshot.get("job") if isinstance(snapshot, dict) else None
            if isinstance(last, dict) and last.get("status") not in ("queued", "running", "awaiting_approval"):
                return job_id, str(last.get("status") or "unknown"), str(last.get("error") or "")
            if last is None and isinstance(snapshot, dict):
                # The service no longer owns this job and the queue has no row
                # for it: use the terminal history row instead of waiting out
                # the whole budget and mislabelling a finished job as timeout.
                terminal = self._terminal_from_history(job_id)
                if terminal is not None:
                    return job_id, *terminal
                return job_id, "unknown", "the service no longer reports this job"
            # The wait is interruptible by stop(); the old bare sleep kept the
            # daemon thread alive up to 3 minutes after a shutdown request.
            self._stop.wait(min(2.0, max(0.0, deadline - time.time())))
        if self._stop.is_set():
            return job_id, "stopped", "scheduler stopped while waiting for the job"
        # A job that is still running after the wait budget is not a success.
        # Stop it and wait for a terminal state before the caller may schedule
        # a retry: a retried send/pay/delete while the original is alive is a
        # duplicate side effect. Until the service stops reporting the id, the
        # only safe outcome is "no retry".
        stopper = getattr(self.service, "stop", None)
        if callable(stopper):
            try:
                stopper(job_id)
            except Exception:
                pass
            stop_deadline = time.time() + 5.0
            while time.time() < stop_deadline and not self._stop.is_set():
                try:
                    snapshot = self.service.status(job_id)
                except Exception:
                    terminal = self._terminal_from_history(job_id)
                    if terminal is not None:
                        return job_id, *terminal
                    break
                last = snapshot.get("job") if isinstance(snapshot, dict) else None
                if isinstance(last, dict) and last.get("status") not in (
                        "queued", "running", "awaiting_approval"):
                    return job_id, str(last.get("status") or "unknown"), str(last.get("error") or "")
                if last is None:
                    terminal = self._terminal_from_history(job_id)
                    if terminal is not None:
                        return job_id, *terminal
                    break
                self._stop.wait(0.25)
            return job_id, "timeout-running", (
                problem or f"no terminal status within {timeout}s") + "; job stop was not confirmed"
        return job_id, "timeout", problem or f"no terminal status within {timeout}s"

    @staticmethod
    def _number(value, default=0.0):
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return default
        return number if number == number and abs(number) != float("inf") else default

    def _run_item(self, item, manual=False):
        job_id, status, error = None, "started", ""
        due_at = self._number(item.get("next_at"), 0.0) or time.time()
        every = int(self._number(item.get("every_seconds"), 3600))
        every = max(60, min(every, 365 * 86400))
        try:
            started = self.service.start(item.get("task", ""))
            job_id, status, error = self._wait_for_job(started)
        except Exception as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
        with self.lock:
            current = next((row for row in self.items if row.get("id") == item.get("id")), None)
            if current is not None:
                current["last_run"] = time.time()
                current["last_status"] = status
                current["last_job_id"] = job_id
                current["runs"] = int(current.get("runs") or 0) + 1
                if status.startswith("timeout"):
                    # The job may still be alive or may have performed part of
                    # its side effect. Never schedule a short retry for it.
                    current["last_error"] = error[:500]
                    if manual:
                        self._notify("Jarvis task failed", f"{current.get('name')}: {error[:180]}")
                    else:
                        current["retry_count"] = 0
                        self._reschedule(current, due_at, every)
                        self._notify("Jarvis task timed out", f"{current.get('name')}: {error[:180]}")
                elif status in ("error", "stopped", "failed", "timeout", "unknown"):
                    current["last_error"] = error[:500]
                    if manual:
                        # A manual run is an explicit probe, not a missed slot:
                        # it must not consume retries or move the next run.
                        self._notify("Jarvis task failed", f"{current.get('name')}: {error[:180]}")
                    else:
                        retries = int(current.get("retry_count") or 0)
                        maximum = int(current.get("max_retries") or 0)
                        if retries < maximum:
                            current["retry_count"] = retries + 1
                            current["next_at"] = time.time() + min(300, 30 * (retries + 1))
                            self._notify("Jarvis task retry", f"{current.get('name')}: {error[:180]}")
                        else:
                            self._reschedule(current, due_at, every)
                            self._notify("Jarvis task failed", f"{current.get('name')}: {error[:180]}")
                else:
                    current["last_error"] = ""
                    current["retry_count"] = 0
                    if not manual:
                        self._reschedule(current, due_at, every)
            try:
                # Persist while holding the same lock that mutates the rows;
                # saving after the lock let another update overwrite this one.
                self._save()
            except Exception as save_error:
                # A transient OSError in the scheduler used to kill the whole
                # daemon thread and silently stop every future scheduled job.
                self._notify("Jarvis scheduler", f"Saving schedules failed: {save_error}")
        try:
            from operator_modules import reminders
            reminders.notify_job_finished(
                self.path.parent,
                job_id=str(job_id or ""),
                job_name=str(item.get("name") or item.get("task") or ""),
                status=str(status or ""),
            )
        except Exception:
            pass

    @staticmethod
    def _reschedule(item, due_at, every):
        """Next run gets a planned time basis so long jobs do not push the cadence.

        ``now + every`` made each interval ``every + how long the last run took``
        (an hourly task with a 20-minute job became an 80-minute task). Counting
        from the slot that became due and skipping fully missed periods keeps the
        cadence and never runs more than one job per missed period.
        """
        scheduled = due_at + every
        now = time.time()
        while scheduled <= now:
            scheduled += every
        item["next_at"] = scheduled

    def _check_heartbeat(self):
        from operator_modules import heartbeat
        return heartbeat.check(self.path.parent, self.list())

    def _check_watches(self):
        from operator_modules import watch_pages
        return watch_pages.run_due(self.path.parent)

    def _check_reminders(self):
        from operator_modules import reminders
        return reminders.run_due(self.path.parent)

    def _loop(self):
        while not self._stop.is_set():
            if time.monotonic() - self._heartbeat_checked >= 30:
                self._heartbeat_checked = time.monotonic()
                for check in (self._check_heartbeat, self._check_watches, self._check_reminders):
                    try:
                        check()
                    except Exception as error:
                        print(f"[heartbeat/watch/reminders] check failed: {type(error).__name__}", flush=True)
            try:
                with self.lock:
                    now = time.time()
                    due = [dict(item) for item in self.items
                           if item.get("enabled", True)
                           and self._number(item.get("next_at"), 0.0) <= now]
            except Exception as loop_error:
                self._notify("Jarvis scheduler", f" Tick error: {loop_error}")
                self._stop.wait(5)
                continue
            for item in due:
                try:
                    self._run_guarded(item)
                except Exception as item_error:
                    self._notify("Jarvis scheduler", f" Tick error: {item_error}")
            # Sleep until the nearest scheduled slot instead of a fixed 10 s
            # tick; stop() interrupts a long nap immediately.
            try:
                with self.lock:
                    enabled_times = [self._number(item.get("next_at"), 0.0)
                                     for item in self.items
                                     if item.get("enabled", True)]
                until_periodic = max(0.5, 30.0 - (time.monotonic() - self._heartbeat_checked))
                if enabled_times:
                    horizon = min(enabled_times)
                    until_job = max(0.5, horizon - time.time()) if horizon > time.time() else 0.5
                    nap = min(until_periodic, until_job)
                else:
                    nap = until_periodic
            except Exception:
                nap = 10.0
            self._stop.wait(float(nap))

