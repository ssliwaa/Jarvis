"""Hands-free voice & text Q&A bridge between sandboxed agents and the owner.

When an agent inside bwrap executes `jarvis-team ask owner "..." --wait 120`,
`agent_team` registers the question here, publishes an instant SSE event to
Mission Control, speaks it aloud via `tts_piper` (respecting GNOME Do-Not-Disturb
and active call microphones), and lets the owner reply by voice or text.
"""

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import agent_cli


def _store_path() -> Path:
    return agent_cli.ROOT.parent / 'owner_questions.json'


@contextmanager
def _store_lock():
    base = agent_cli.ROOT.parent
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(base / '.owner_q.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _load_questions() -> dict[str, dict]:
    path = _store_path()
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_questions(items: dict[str, dict]) -> None:
    path = _store_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.tmp-{os.getpid()}-{os.urandom(4).hex()}-{time.time_ns()}')
    try:
        tmp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding='utf-8')
        os.chmod(tmp, 0o600)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _speak_async(text: str) -> None:
    def _worker():
        try:
            import wayland_voice
            gen_id = wayland_voice.BARGE_IN.begin_utterance()
            if not wayland_voice.BARGE_IN.is_current(gen_id):
                return
            import tts_piper
            for fn_name in ('speak', 'say', 'synthesize_and_play'):
                fn = getattr(tts_piper, fn_name, None)
                if callable(fn):
                    fn(text)
                    return
        except Exception:
            return

    threading.Thread(target=_worker, name='jarvis-voice-bridge-tts', daemon=True).start()


def enqueue_owner_question(project_id: str, req_id: str, from_agent: str,
                           question: str, speak: bool | None = None) -> dict:
    """Register a pending agent->owner question, push SSE, and read aloud if DND is clear."""
    clean_id = str(req_id or '').strip()
    clean_q = str(question or '').strip()
    if not clean_id or not clean_q:
        raise ValueError('req_id and question are required.')

    now = round(time.time(), 3)
    with _store_lock():
        items = _load_questions()
        if clean_id in items:
            return items[clean_id]
        entry = {
            'id': clean_id,
            'project_id': str(project_id or '').strip(),
            'from': str(from_agent or 'agent').strip(),
            'question': clean_q[:2000],
            'created_at': now,
            'status': 'pending',
            'answer': '',
            'answered_at': None,
            'source': '',
        }
        if len(items) >= 80:
            oldest = sorted(items.values(), key=lambda r: float(r.get('created_at') or 0))[:-79]
            for old in oldest:
                items.pop(old.get('id', ''), None)
        items[clean_id] = entry
        _save_questions(items)

    try:
        import event_bus
        event_bus.publish('owner.question', entry)
    except Exception:
        pass

    if speak is True:
        should_speak = True
    elif speak is False:
        should_speak = False
    else:
        handsfree_env = os.environ.get('JARVIS_VOICE_HANDSFREE', '0').strip()
        if handsfree_env in ('1', 'true', 'yes'):
            try:
                import wayland_voice
                should_speak = not wayland_voice.dnd_status().get('dnd', False)
            except Exception:
                should_speak = True
        else:
            should_speak = False

    if should_speak:
        _speak_async(f"Agent {entry['from']} pyta: {clean_q[:260]}")
    return entry


def pending_owner_questions(project_id: str = '') -> list[dict]:
    """Return unanswered questions waiting for the owner."""
    items = _load_questions()
    pid = str(project_id or '').strip().lower()
    rows = [
        q for q in items.values()
        if isinstance(q, dict)
        and q.get('status') == 'pending'
        and (not pid or str(q.get('project_id') or '').lower() == pid)
    ]
    rows.sort(key=lambda r: float(r.get('created_at') or 0))
    return rows


def answer_owner_question(answer_text: str, req_id: str = '',
                          project_id: str = '', source: str = 'text') -> dict:
    """Deliver the owner's reply back to the waiting sandboxed agent and team chat."""
    clean_ans = str(answer_text or '').strip()
    if not clean_ans:
        raise ValueError('Answer cannot be empty.')

    with _store_lock():
        items = _load_questions()
        target_id = str(req_id or '').strip()
        if not target_id:
            pending = [
                q for q in items.values()
                if q.get('status') == 'pending'
                and (not project_id or q.get('project_id') == project_id)
            ]
            pending.sort(key=lambda r: float(r.get('created_at') or 0))
            if not pending:
                raise ValueError('Brak oczekujących pytań od agentów.')
            target_id = pending[0]['id']

        entry = items.get(target_id)
        if not isinstance(entry, dict):
            raise ValueError(f'Nieznane ID pytania: {target_id}')

        now = round(time.time(), 3)
        entry['status'] = 'answered'
        entry['answer'] = clean_ans[:4000]
        entry['answered_at'] = now
        entry['source'] = str(source or 'text')[:24]
        items[target_id] = entry
        _save_questions(items)

    try:
        import event_bus
        event_bus.publish('owner.answered', entry)
    except Exception:
        pass

    pid = entry.get('project_id') or ''
    to_agent = entry.get('from') or 'all'
    if pid:
        import agent_team
        pdir = agent_team.project_root(pid)
        req_dir = pdir / 'requests'
        with agent_team._file_lock(req_dir / '.lock'):
            req_file = req_dir / f'req-{target_id}.json'
            if req_file.is_file():
                try:
                    rq = json.loads(req_file.read_text(encoding='utf-8'))
                    rq['status'] = 'answered'
                    req_file.write_text(json.dumps(rq, ensure_ascii=False, indent=2), encoding='utf-8')
                except (OSError, ValueError):
                    pass
            resp_file = req_dir / f'resp-{target_id}.json'
            resp_file.write_text(json.dumps({
                'id': target_id,
                'from': 'owner',
                'to': to_agent,
                'answer': entry['answer'],
                'answered_at': now,
            }, ensure_ascii=False, indent=2), encoding='utf-8')
        agent_team.post_message(
            pid,
            sender='owner',
            to=to_agent,
            role=entry['source'],
            kind='answer',
            text=f"[reply:{target_id}] {entry['answer']}",
            _trigger_wake=False,
        )

    return entry


def transcribe_and_answer(audio_bytes: bytes, language: str = 'pl',
                          req_id: str = '', project_id: str = '') -> dict:
    """Transcribe spoken owner audio via stt_cloud/stt and answer the waiting question."""
    if not audio_bytes:
        raise ValueError('Empty audio payload.')
    import stt
    wav, _stats = stt.prepare_take(audio_bytes)
    try:
        import stt_cloud
        use_cloud = stt_cloud.available()
    except Exception:
        use_cloud = False
    if use_cloud:
        heard = stt_cloud.transcribe(wav, language, content_type='audio/wav')
    else:
        heard = stt.transcribe(wav, language)
    transcript = str((heard or {}).get('text') or '').strip()
    if not transcript:
        raise ValueError('Nie udało się rozpoznać odpowiedzi głosowej.')
    answered = answer_owner_question(transcript, req_id=req_id, project_id=project_id, source='voice')
    return {'ok': True, 'heard': transcript, 'question': answered}
