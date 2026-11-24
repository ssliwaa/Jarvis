# Knowledge Galaxy

Local 3D map and grounded chat over `~/notes`.

**Jarvis** is an AI assistant that runs on your machine: a 3D knowledge galaxy over your
markdown vault, grounded chat with numeric citations, voice in/out, a REA page teardown,
a ~115-tool computer **Operator** with approval gates and self-modification, plus a built-in
**MCP server**. The server is loopback-only; your notes, memory, secrets and config stay on
disk (outside the repo). Only model calls leave the machine — DeepSeek API by default, key
from `DEEPSEEK_API_KEY`, never stored in the repo. MIT.

> Quick start: `python3 build.py && .venv/bin/python server.py` → http://127.0.0.1:4700

<details>
<summary><b>Contents</b></summary>

- [Open](#open)
- [Start / rebuild](#start--rebuild)
- [Private configuration](#private-configuration)
- [How the galaxy and brain work](#how-the-galaxy-and-brain-work)
- [Example questions from the actual vault](#example-questions-from-the-actual-vault)
- [Desktop app](#desktop-app)
- [Supervisor, routing and queue](#supervisor-routing-and-queue)
- [Voice](#voice)
- [Answer latency (streaming lane)](#answer-latency-streaming-lane)
- [Self-modification lane](#self-modification-lane)
- [Operator reliability, modules and undo](#operator-reliability-modules-and-undo)
- [P1: memory, durable sessions, skills and MCP](#p1-memory-durable-sessions-skills-and-mcp)
- [P2: local office, system, apps, organizer and briefing](#p2-local-office-system-apps-organizer-and-briefing)
- [Studio UI](#studio-ui)
- [Operator agent](#operator-agent)
- [Butler persona and control tags](#butler-persona-and-control-tags)
- [Remember that: live captures](#remember-that-live-captures)
- [Reverse-engineering bay (REA)](#reverse-engineering-bay-rea)
- [Ephemeral teardown browser](#ephemeral-teardown-browser)
- [Evidence capture (REA + Jarvis)](#evidence-capture-rea--jarvis)
- [Teardown: read, hear, keep](#teardown-read-hear-keep)
- [Voice teardowns and the live card](#voice-teardowns-and-the-live-card)
- [Proof before the camera](#proof-before-the-camera)
- [Live preflight — completion gate](#live-preflight--completion-gate)
- [Regression tests](#regression-tests)
- [License](#license)

</details>

## Open

http://127.0.0.1:4700

No npm, bundler, frontend build or framework. The first load requires internet access for the exact-version 3D CDN scripts. The indexer uses only Python's standard library. The server's runtime dependencies are the official `anthropic` package and the free `edge-tts` bridge; the browser agent additionally uses Playwright and a local Chromium.

## Start / rebuild

From this project directory:

    python3 build.py
    .venv/bin/python server.py

The supplied isolated environment is already installed. For a fresh install:

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.txt

Run `python3 build.py` after changing your notes, then restart the server and reload the browser so graph ids and retrieval agree. Indexing is deterministic, includes every `.md` (also `.MD`) below the notes root, and does not modify the notes. Symlinks escaping the vault fail closed.

Optional index paths:

    python3 build.py --notes /path/to/notes --output viewer/graph-data.js

The server defaults to the requested vault. For a custom vault use the Python `create_server(notes_root=...)` interface as well; changing only the indexer path does not change the server root.

## Private configuration

Jarvis uses the official **DeepSeek API** by default. The key is not stored in `config.json`; it is read from `DEEPSEEK_API_KEY` in the process environment (e.g. `~/.hermes/.env` or an exported variable). The main config lives **outside the project tree** at `$XDG_CONFIG_HOME/jarvis/config.json` (default `~/.config/jarvis/config.json`, override with `JARVIS_CONFIG`); on first start a legacy `<project>/config.json` is migrated there automatically and never tracked by git. The safe template is `config.example.json`:

    {
      "provider": "deepseek",
      "model": "deepseek-flash",
      "models": ["deepseek-flash"]
    }

`models` is optional; it is a fallback ladder, not a replacement for `model`. The primary `model` is always prepended and duplicates are removed. Up to five ids are accepted. A retryable transport, rate-limit, unavailable-model or server failure steps to the next id; authentication, permission and credit failures do not silently switch models. The answer response includes `model` only when a fallback actually answered. A legacy `provider: "openrouter"` config still works for tests or migration, but the production config is DeepSeek.

The application config is excluded from version control and has mode 0600. The server rereads it for each question. Writable state lives under `~/.jarvis-tools` (override with `JARVIS_STATE`), which is forced to 0700; session/memory/vector databases and their `-wal`/`-shm` sidecars are created as 0600. A maintenance thread takes an online SQLite backup every six hours into `~/.jarvis-tools/backups/db-<stamp>` (five generations kept; each copy is 0600), and optional artifact retention runs only with `JARVIS_ARTIFACT_PRUNE=1`. Never copy the DeepSeek key into `config.json`, HTML, JavaScript or `viewer/`; it remains in the Hermes environment.

DeepSeek is called through its OpenAI-compatible `/chat/completions` endpoint by `provider_client.py`, while Jarvis keeps its existing Anthropic-shaped message/tool contract. `deepseek-flash` is the current API id; the retired `deepseek-chat`/`deepseek-reasoner` names were replaced. Requests explicitly send `thinking: disabled`: DeepSeek enables thinking by default, and a thinking tool loop requires every assistant turn to echo `reasoning_content` — a field this adapter intentionally never surfaces. Chat retries once with a larger token budget if no visible answer text is returned and never displays reasoning blocks. Authentication, unavailable model, rate limit, credit and connection failures produce clean UI errors instead of tracebacks. Paid paths are protected by local token buckets (`JARVIS_PAID_RATE_PER_MIN`, `JARVIS_AGENT_RATE_PER_MIN`, `JARVIS_TTS_RATE_PER_MIN`; default 30/10/60 per minute) and an optional daily reservation (`JARVIS_DAILY_CALL_LIMIT`, counted for chat, Operator/teardown, TTS, self-modification and memory-model refresh).

<details>
<summary><b>How the galaxy and brain work</b></summary>


- Numeric node ids are EXACTLY their positions in `GRAPH.nodes`, including index 0.
- Labels come from filenames; groups are immediate parent folders; excerpts are up to 700 characters.
- Undirected links join title mentions, explicit wikilinks, or notes sharing wikilink targets. Duplicate links/self links are removed.
- Retrieval is a standard-library SQLite FTS5/BM25 index built in memory from the vault, with a 12× title weight and a small recency boost. Polish text is diacritic-folded, and long query words are also tried with one or two trailing letters removed so `samochodu` can reach a note saying `samochód`. The index is refreshed when note mtimes/sizes change; the original keyword scorer remains as a fail-safe if FTS5 is unavailable. The semantic lane stores one vector per overlapping note window (1,200 characters with 200 characters of overlap, at most 24 windows), deduplicates matches back to a single note id, and migrates existing whole-note rows on first open. At most six relevant notes are passed as evidence, with their numeric indexes. Note text is wrapped in explicit `<<<UNTRUSTED source=note:N>>>` blocks, and control-tag delimiters inside it are escaped before the model sees them.
- Chat answers from this evidence as a dry British butler: at most one witty sentence plus essential facts, without padding, and numeric note citations. If retrieval finds no usable source, or the model declines/cites outside the supplied notes, Jarvis calls DeepSeek a second time in a clearly-labelled general-knowledge lane: `mode: general`, `grounded: false`, `nodes: []`, no fake citations. For price, availability, current-fact and explicit web questions it first searches the public web and passes dated result snippets to the model; used links come back as `web_sources`, the answer cites `[W1]`… and the UI shows a clickable **WEB SOURCES** list. Short server-side history allows follow-ups. No shell or arbitrary execution is exposed.
- The persona's `CAPABILITIES` and `LIMITS` are generated from the same live registry exposed at `GET /capabilities`. The prompt cannot deny a listed action or claim an unlisted one without contradicting the running system. `GET /retrieval/status` reports whether the live brain is using FTS5 or the keyword fallback, without exposing note text or paths.
- A model reply may return a teardown tag only when the user's own current message contains teardown intent. A tag suggested by a note, a previous turn or a model continuation is rejected and no browser is launched.
- Asking a question shares the retrieved note context and short conversation with DeepSeek. In the general lane no note context is sent, only the question, short conversation, memory and session summary. Merely opening/exploring the galaxy does not send your notes to the model.
- Common credential patterns are scrubbed from note excerpts and retrieval text on a best-effort basis. This is not a guarantee: keep secrets outside the indexed vault.
- Only the `viewer/` directory is served, and path/symlink escapes are rejected. This service is loopback-only, not a hardened public hosting product.

</details>

<details>
<summary><b>Example questions from the actual vault</b></summary>


- Co notatka „plan-treningowy-bieg” mówi o zasadzie 80/20 i strukturze tygodnia?
- Jak działa auto-load z folderu Pobrane według „utorrent-automatyzacja”?
- Jak zaimplementowano wbudowany odtwarzacz opisany w „kino-1.4.45-linux-player”?

</details>

<details>
<summary><b>Desktop app</b></summary>


Jarvis can run as a standalone desktop window instead of a browser tab. The Electron shell lives in `desktop/` and is launched by the **Jarvis** icon on the Desktop or in the application menu:

    ./desktop/jarvis-app.sh

It uses a dedicated window with no address bar or tab strip, checks the local `/health` endpoint, starts `.venv/bin/python server.py` if needed, and stops the server it started when the window closes. If Jarvis is already running, it attaches and leaves that server alone. Electron `45.0.0` is pinned in `desktop/package.json`; repair with `cd desktop && npm install`. The desktop profile is `~/.jarvis-tools/desktop-profile`, separate from the Operator and REA profiles. The Electron sandbox stays enabled by default; a host whose AppArmor policy blocks unprivileged user namespaces can set `JARVIS_ELECTRON_NO_SANDBOX=1` as an explicit local exception. The server remains loopback-only. The launcher can be installed as `~/Desktop/Jarvis.desktop` and `~/.local/share/applications/jarvis.desktop`.

</details>

<details>
<summary><b>Supervisor, routing and queue</b></summary>


The server can be supervised by a `systemd --user` unit instead of a bare background process:

```bash
systemctl --user enable --now jarvis.service
systemctl --user status jarvis.service
journalctl --user -u jarvis.service -f
```

The unit restarts on failure and uses a 30-second watchdog; `GET /services` exposes its state and the Studio Overview has refresh/install/restart controls. The server writes `READY=1` and watchdog pings itself, so a health failure is visible as a service restart rather than a silent dead port.

`router.py` classifies a chat request before any model call. Clear imperatives become an Operator plan; a target-less imperative returns `needs_target` instead of starting a tool. An explicit call — “użyj operatora i otwórz Opera GX”, “przekaż do operatora: …”, `operator: <task>` or `/operator <task>` — routes the action after the prefix to the Operator even when the action verb is not the first word; naming the Operator without a task asks for one. The Operator queue persists to `~/.jarvis-tools/agent-queue.json`; `/agent/queue`, `/agent/queue/resume` and `/agent/stop` expose it, and a restarted server resumes queued tasks unless `JARVIS_RESUME_QUEUE=0`.

Cancelling is a local lane, not a model answer: “cancel this youtube I don’t want it”, “cancel it”, “stop the music”, “anuluj to”, “przestań”, “nie chcę tego” and “zapomnij o tym” are answered from the live Operator state with no model call. A cancel may name its subject (youtube, music, spotify, a task) and narrow the target to the matching job or queued row; “cancel everything” / “anuluj wszystko” clears the active job *and* the queue in one call (`AgentService.cancel_all`, which empties the queue before stopping so the freed slot cannot promote the next task). The reply names the task it stopped, waits up to six seconds (`JOB_STOP_CONFIRM_SECONDS`) for the job to actually leave the active slot, and says “nadal kończy bieżący krok” instead of claiming a stop it has not confirmed. The pattern is deliberately bounded — verb, one determiner, a known subject, an explicitly anchored reason — so “zatrzymaj proces Opera GX”, “zamknij youtube” and “cancel my subscription” still belong to the Operator or the chat, not to the cancel lane.

Approval is one-time and token-bound: the token is attached to the pending action, expires with the approval window, and is never accepted twice. `write_file` diffs and critical-risk flags are shown in the panel.

Serving is cheap on repeated views: the graph and note-list data are cached and only rebuilt when the underlying notes actually change (the graph cache keys on the note tree's mtime and size; note lists also key on per-note file stats). Static Studio assets answer `ETag`/`If-None-Match` with **304** (from a no-cache handshake, so edits are always revalidated), are gzip-compressed when 8 KiB or larger, and `graph-data.js` stays `no-store` because the viewer depends on its freshness. Only real static files accept `HEAD`; other routes answer 405. `/memory/events` clamps its limit to 1–100.

</details>

<details>
<summary><b>Voice</b></summary>


Answers use Edge TTS by default when `edge-tts` is installed, with the British neural voice `en-GB-RyanNeural`. The server exposes a loopback-only `POST /tts` (text plus an approved voice) and `GET /tts/status`; the browser collects the MP3 and plays it through an `Audio` element. If Edge is unavailable, the same speak function falls back to the browser's speech synthesis. Edge receives only the sentence being spoken, never the vault, conversation history, local paths or credentials. It is a free Microsoft service but it requires internet access and sends that sentence to Microsoft.

The page displays “Hello, sir.” on load and refresh; its first trusted click speaks exactly that line, respecting browser activation rules. The visible note count is read from GRAPH.nodes, never hardcoded or spoken as part of the greeting. `?mute=1` blocks the Edge request and playback as well as browser speech. The microphone button uses `webkitSpeechRecognition` with a standard-API fallback; English (UK) and Polish recognition are selectable. The picker starts from the system locale (a Polish `navigator.language` selects Polski) and an explicit choice is stored in local storage, so a reload no longer silently returns to English. Electron ships Chromium without Google's speech backend, so in the desktop window recognition always dies with a `network` error; there the button records with `MediaRecorder` and posts the blob to the loopback-only `POST /voice/transcribe`, where `stt.py` runs ffmpeg and whisper.cpp on this machine (`GET /voice/status` reports the model and binary). Install or repair that path with `scripts/install-stt.sh` (builds whisper.cpp v1.9.5 and fetches the quantised `base` model, 57 MB, into `~/.jarvis-tools`); `JARVIS_STT_MODEL_SIZE=small scripts/install-stt.sh` fetches the more accurate 190 MB `small` model, which `stt.py` prefers automatically when present. When `GROQ_API_KEY` is configured (in the environment or `~/.hermes/.env`; `JARVIS_GROQ_API_KEY` wins), every take goes first to `stt_cloud.py`: Groq's `whisper-large-v3` transcribes it in about half a second and answers a Polish question that whisper-small mangled into hallucinations (`whisper-large-v3-turbo` hallucinates plausible words out of pure noise — large-v3 returns lone punctuation instead, which the cloud lane strips — so the non-turbo model is the configured engine). `stt.py:prepare_take` gates every request first: a decode that fits under "too short / silent / too weak" never reaches either engine, and the gate log (with the measured seconds and dBFS) lands in the journal. The key is optional — without it, and whenever the cloud refuses (no network, expired or throttled key), the request falls back to the silent local engine above. The model can be overridden with `JARVIS_WHISPER_MODEL`, the binary with `JARVIS_WHISPER_BIN`, and the default language with `JARVIS_STT_LANGUAGE` (Polish by default). The recognition-language picker is sent to the local transcriber too, so English (UK) and Polski apply in the desktop window as well. `JARVIS_STT_AUDIO_CTX` (default `auto`) controls the encoder window: `0` keeps Whisper's full 30-second window, a number pins it, and `auto` picks a measured bucket from the recording length. On this host the auto buckets cut a 3.2 s question from 2.01 s to about 0.7 s with `base` (about 1.9 s with `small`); a degenerate result is retried with the full window. Before Whisper runs, leading and trailing silence is trimmed and a quiet microphone is lifted by up to +48 dB: a rescued take that peaks around −66 dBFS (a distant laptop mic) lands in the speech range instead of being thrown away, while a take quieter than −68 dBFS has no speech-shaped signal at all and is named as too weak before it reaches a model. The cloud lane additionally filters hallucinations with whisper's own per-segment verdicts (no_speech_prob ≥ 0.65, avg_logprob below −1.0, compression_ratio above 2.6 or fewer than two letters means a segment is dropped), and a transcript composed exclusively of the politeness-formula noise mold ("Dziękuję.", "Zobaczcie.", "Proszę państwa") is returned as "heard nothing" instead of a fake answer; the local engine applies the same formula filter. Repeated identical sentences and takes made only of bracketed non-speech tags (“[Muzyka]”) are discarded rather than shown as answers. Nothing about a recording leaves the machine.

The voice toolbar lists the curated Edge voices (Ryan, Thomas, Sonia and Libby in British English; Marek and Zofia in Polish), a browser Auto option, and the installed browser voices. The choice is persisted in local storage. “Auto — Edge British” is the default. The selected spoken voice — never the microphone — decides the answer language: an English voice earns English answers, so the model translates whatever Polish note content matters (the British voice cannot pronounce Polish), while choosing Marek or Zofia keeps Polish answers. Recognition language is about hearing only; a Polish microphone with an English voice still gets an English reply. If a fallback lane still returns Polish, the server makes one translation call before returning the answer, so an English voice never reads Polish text; a failed translation keeps the original answer rather than losing it. Edge replies are synthesized sentence by sentence: the first complete sentence is fetched and spoken while the model is still streaming the rest, and the next sentence downloads while the current one plays. On this host a 116-character first sentence takes about 2.7 s to synthesize versus about 8.6 s for an 843-character answer, so the voice starts several seconds sooner and the streamed panel accumulates every delta instead of showing only the newest fragment. Browser voices keep their native queue. Browser voices exposed by speech-dispatcher as espeak-ng variants (for example “English (Great Britain)+Adam”) are filtered out, because the raw list can contain thousands of novelty variants. A small input meter uses `getUserMedia` plus the Web Audio API while the microphone is armed, so a silent or wrong microphone is visible before asking a question. In the local recording path the meter analyses the recorder's own stream instead of opening a second microphone capture; a second PipeWire capture can land on a gated device and make a working recorder look silent. Because some devices deliver unusably quiet audio even at the system's 100% settings, the recording graph inserts a fixed pre-gain (a `GainNode` between the mic and `MediaRecorder`, default +12 dB) before the encoder: the uploaded take, its transcription and the meter all show the boosted level. Store a different value in dB under `localStorage['galaxy.mic-boost']` (for example `0` to disable, `20` to lift hard); the server-side rescue in `stt.prepare_take` (up to +48 dB) and the hallucination filters stay behind it as the second line of defence.

Hold Ctrl+Space while this page has focus for push-to-talk. Releasing the keys stops capture but lets the recognizer deliver its final phrase before the normal finish window; it does not abort the sentence. While the desktop app is running, `Ctrl+Shift+Space` works system-wide: tap once to start recording and tap again to stop and send, even while another application has focus. A local take is capped at 60 seconds. The in-page shortcut is deliberately ignored while typing in an input, textarea or select. If a `/chat` answer is still pending after 700 ms, Jarvis speaks one short acknowledgment (“One moment, sir.”); the real answer replaces it when it arrives. The acknowledgment obeys the same mute guard.

The Edge route is the quality upgrade chosen for this machine; the browser route remains the private, offline fallback. Local wake-word detection is opt-in through the **Hey Jarvis** button: it keeps the microphone open, processes the phrase locally and starts a six-second voice take after detection. Pause briefly between the wake phrase and the command; the existing transcription path processes the take. The button stops the microphone, and closing the page stops it too. Raw-PCM acoustic echo cancellation, audio-device selection and lip-sync are still not included; those require a native audio service. Edge TTS does not receive note contents or credentials, but the spoken sentence leaves the machine; use the Browser voice option when that matters.

Final recognition fragments are combined over the single `FINISH_MS = 900` window at the top of `viewer/voice.js`. New speech resets the window; interim speech never sends an incomplete fragment. “stop” and “wait” bypass it immediately and run locally. Extend `galaxy.voice.routes` with pattern/handler pairs rather than modifying the recognition core. The small voice line displays Listening, Thinking and Speaking, including simultaneous capture/output.

A lexical echo guard remembers the last spoken answer for `ECHO_TAIL_MS = 2500` and drops transcripts that exactly match it, are a long substring of it, or share at least 70% of their tokens. It runs on both recognition paths, including the local `POST /voice/transcribe` result, and the recorder asks for `echoCancellation`, `noiseSuppression` and `autoGainControl` so speaker bleed is reduced before the transcript exists. It works from the transcript because the Web Speech API does not expose the microphone waveform; it is not a full acoustic echo canceller. Short user commands such as “stop” still take the immediate route. The guard's event/timer tests cover own-sentence echo, a genuinely different user question, the post-speech tail, and user interruption.

With no `GROQ_API_KEY` present, no paid speech API or account is used. When that key is configured, recorded audio blobs leave for Groq's transcription endpoint (audio only, never the vault, conversation history, local paths or credentials); the free tier covers casual use and `whisper-large-v3`-listed rates run about $0.11 per hour of audio. `edge-tts==7.3.1` is pinned in `requirements.txt`; it calls Microsoft's free endpoint, so a sentence leaves the machine and a network connection is needed for each new utterance. The browser may still send microphone audio to its vendor's recognition service; offline recognition (with the cloud lane refusing) and installed synthesis voices depend on the browser/system. In a normal browser the local engine can be selected with `localStorage.setItem('galaxy.stt', 'local')` followed by a reload; without that preference Chrome keeps its vendor recogniser. Headphones avoid feedback while the mic listens for interrupts during speech. Microphone permission is allowed only for this origin.

Full click/say/see/hear acceptance steps: `VOICE-TEST-PLAN.md`. Automated UI/voice-event verification: `.venv/bin/python verify_voice.py` (uses speech doubles, never actual audio). Evidence: `artifacts/voice-verification.json`. Physical microphone and audible voice quality remain a manual check.

</details>

<details>
<summary><b>Answer latency (streaming lane)</b></summary>


`POST /chat/stream` streams the same answer the batch lane composes — one code path (`app._chat`, now with a `stream_emit` callback) drives both, the stream worker merely forwards model text as it is written (SSE frames `delta`, then one final `result` frame carrying the identical batch-shaped payload the viewer already handled; `_remember`/memory capture still run server-side on that final frame). The viewer renders each delta into the answer panel and swaps in the final result at the end; any stream failure falls back to the batch `POST /chat`, and a stream that carried deltas but died is never silently re-asked in batch, because a second run could repeat an Operator action. Errors during streaming surface as an `error` SSE frame instead of breaking the chunked response. DeepSeek's adapter streams OpenAI-compatible chat SSE (`provider_client.DeepSeekMessages.create(..., stream=True)`), retries only fully-before-first-byte failures, and meters the usage the stream reports (`stream_options.include_usage`). Two local reflexes keep common questions off the model entirely: clock/date questions are answered in-process, and news verticals (`web_research.is_news_query`) skip the notes pass, which only burned a full model round-trip before the general lane answered anyway. Measured on this host: first rendered text lands about 1 s after the question (batch previously waited 3.6–6.7 s for the whole answer), and a clock question answers in 1–2 ms.

</details>

<details>
<summary><b>Self-modification lane</b></summary>


Jarvis keeps the three Brahma mechanisms in `self_modify.py`:

- **Learned rules** — `~/.jarvis-tools/selfmod/learned-rules.json`; user style directives are injected into each Operator prompt with an explicit “preferences only, never override safety” header. `GET /self/rules`; mutating `POST /self/rules` needs `confirm:true`. Rules that try to bypass approvals, exfiltrate secrets or ignore safety are rejected.
- **Skill Forge** — `POST /self/forge` with `{goal,name?}` returns a **proposal** (HTTP 202), preview and one-time token; it does not write yet. `SkillCrucible` uses an AST allowlist and runs the generated test cases in a child process with a temporary HOME, resource limits and a timeout; every case needs `expect`, `expect_contains` or `expect_error`, and missing JSON output is a failure. `POST /self/forge/apply` with `{proposal_id,token}` writes `features/<name>.py` plus the package manifest and test cases. `POST /self/run` with `{name,arguments,confirm:true}` executes an existing skill through a disposable child worker, never by importing it into `server.py`.
- **Auto-Heal** — `POST /self/heal` with `{traceback,notes?}` returns a diff proposal and one-time token (HTTP 202). `POST /self/heal/apply` applies the stored patch only if the source hash still matches; it writes a timestamped backup, runs `py_compile`, records the applied hash and requires a restart for the live process. `POST /self/rollback` with `{patch_id?,confirm:true}` refuses a blind rollback if the file changed after the patch. Verification runs against the **staged** candidate (the patch is compiled and imported from a shadow directory first, so a patch that breaks its own module is caught before it lands), and the Import smoke test only soft-passes for genuinely missing third-party packages. A Skill Forge upgrade keeps the replaced source in `features/.versions/<name>.<stamp>.py.bak` instead of a dotfile beside the skill, so the backup can no longer be re-imported as a phantom skill.

Safety boundary: the Crucible worker, the benchmark harness and the runtime worker are child processes wrapped by the same bubblewrap sandbox as the bench (read-only tree, private `/tmp`, no network) plus per-child rlimits (CPU, file size, descriptors, address space) — this is **not an OS sandbox** against a determined attacker, and generated code still runs with the user's permissions. The AST policy blocks the `os.system` process family, import aliases (`import os as o`), `from os import system`, dynamic `getattr` on `os`/`sys`, `sys.modules`, dunder escape hatches (`__subclasses__`, `__globals__` …) and dunder string literals. Staged verification runs with the live project tree read-only in a disposable HOME, and the Crucible harness owns the verdict instead of trusting output printed by generated code. `GUARDED_FILES` includes `browser_agent.py`, `server.py`, `self_modify.py`, `evolution.py`, `provider_client.py`, `router.py`, `service_control.py`, `operator_verify.py`, `undo_center.py`, memory/session stores and preflight; they require the full staged verification pipeline. `BLOCKED_FILES`/`BLOCKED_DIRS` (config, `.venv`, `.git`, `viewer`, `desktop`, `operator_modules`, …) are refused. The Operator's `http_request` refuses loopback/private targets (including every redirect hop), so a model cannot reach `/self/*` through its own HTTP tool. The running process may need a restart after a source patch because Python has already imported the old module; the endpoint says so rather than claiming a live reload.

</details>

<details>
<summary><b>Operator reliability, modules and undo</b></summary>


- `operator_verify.py` attaches an `outcome` and `verification` to every Operator tool result. `done` requires an observed effect (file content, process status, exit code, loaded URL); a request that was merely delivered is `unverified`; a failed check is `failed`.
- `tool_registry.py` discovers one-file tools from `operator_modules/`. A module declares `TOOL` with a name, description, JSON input schema, handler and optional `approval: true`. Discovery rejects collisions and malformed schemas; `/agent/status` exposes `module_registry: true`.
- `undo_center.py` keeps the last 20 reversible file operations in `~/.jarvis-tools/undo.json` (0600). An unparseable stack file is preserved beside the state file as `undo.json.corrupt-<timestamp>` instead of being silently emptied by the next write. `write_file` records its backup and `delete_path` records its trash path; `undo_last` and `POST /undo` with `{confirm:true}` reverse them. Shell and browser actions are not automatically reversible and are reported as such.
- `checkpoint_manager.py` — transparent shadow-git snapshots under `~/.jarvis-tools/checkpoints` (one bare store, content-addressed objects shared by projects). Before `write_file`, `delete_path`, `restore_file`, destructive/likely-mutating shell or PTY work, an organizer move, a document write and an applied self-heal, the owning project is snapshotted at most once per Operator step; the model never sees a checkpoint tool. `git add` runs with an isolated config and a per-project index, so no `.git` state leaks into the user's tree. Excludes cover secrets (`.env`, `.ssh`, keys), `config.json`, `.venv`, `node_modules`, build/media output, databases and `artifacts/`. Per-project refs keep 20 snapshots by default and the store is capped at 500 MB; `JARVIS_CHECKPOINT_*` tunes both. A ledger records hashes of files Jarvis wrote, so **safe restore** reverts agent edits while preserving user hand-edits; **full restore** returns the whole directory and removes files created after the snapshot. `GET /checkpoints`, `GET /checkpoints/status`, `POST /checkpoints/diff`, `POST /checkpoints/restore` (requires `confirm:true`) and `POST /checkpoints/prune`; the Studio **Files** tab shows the list, diff and both restore modes. The store is maintained by `checkpoint_maintenance.py` (stale refs, conservative orphan detection, size cap); `/health` reports whether the lane is enabled.
- `subagent_manager.py` — the Operator's `delegate` tool spawns independent read-only research children. Each child is a real `AgentJob` on its own thread with its own model client, browser, artifacts and context; the parent sees only the final bounded summary, never the child's transcript or tool history. Actions: `spawn` (up to 3 tasks), `wait`, `list`, `steer`, `cancel`, `result`. Children can read files/PDFs/images, inspect/extract a page, use public web research and read skills; they cannot write/delete, run shell/PTY, use credentials, memory, MCP, scheduler, self-modification, desktop, clipboard, upload/download or page-changing actions, and they cannot spawn further children. `JARVIS_SUBAGENT_MAX_CONCURRENT` (3), `JARVIS_SUBAGENT_MAX_TASKS` (3), `JARVIS_SUBAGENT_MAX_TOTAL` (12) and `JARVIS_SUBAGENT_MAX_STEPS` (12) bound cost; `JARVIS_SUBAGENT_MODEL` optionally pins the child model. A parent cannot finish while a child is active; Stop or parent shutdown cancels the whole tree. A child summary is a self-report and must be verified by the parent for concrete claims.

</details>

<details>
<summary><b>P1: memory, durable sessions, skills and MCP</b></summary>


- `memory_store.py` — SQLite WAL + FTS5 personal memory separate from the notes vault. Categories: identity, preferences, projects, relations, hardware, rules, notes. `GET /memory`, `POST /memory` (`add`, `recall`, `list`, `forget`); the bounded core prompt is injected into chat. The Operator gets the `memory` tool; writes need approval outside Full.
- `session_store.py` — durable chat history under `~/.jarvis-tools/sessions.db`. The live session is restored by its cookie token when it is still fresh; `GET /sessions`, `GET /sessions/search?q=...`, the `session_search` Operator tool, and a bounded `session_summary` to the chat model. A long conversation uses the rolling compaction summary from `context_compressor.py`; the raw turns stay searchable in the archive. **Retention is opt-in only:** nothing is ever pruned by default; set `JARVIS_SESSION_KEEP_DAYS=90` (any positive number of days) to prune turns older than the window at most hourly, as chat turns are written (session rows stay, so conversations remain listed and searchable by summary). A non-numeric value keeps all sessions and prints a warning.
- `context_compressor.py` — head + structured-summary + token-bounded-tail compaction for long chats and Operator jobs. It first prunes old tool-result bodies without an LLM (tool-call arguments stay byte-exact, the newest pending round is spared, identical outputs are back-referenced), then preserves the newest user request and assistant reply, and summarises the middle with a dated handoff that keeps completed actions, files, errors, exact identifiers and verbatim user messages. A failed or truncated summary aborts without dropping messages; otherwise a deterministic fallback still leaves recoverable anchors. `JARVIS_CONTEXT_WINDOW`, `JARVIS_CONTEXT_THRESHOLD_PERCENT`, `JARVIS_CONTEXT_PROTECT_FIRST`, `JARVIS_CONTEXT_PROTECT_LAST`, `JARVIS_CONTEXT_SUMMARY_MODEL`, `JARVIS_CONTEXT_PROACTIVE_PRUNE_TOKENS`, `JARVIS_CONTEXT_SUMMARY_RATIO`, `JARVIS_CONTEXT_TAIL_MODE` and `JARVIS_CHAT_CONTEXT_ROWS` tune it. The Operator archives the exact pre-compaction transcript under the job artifacts and names that file in the handoff; chat state and lineage live in SQLite so a restart does not lose the rolling summary.
- `skills_store.py` + `skills/` — read-only procedures with YAML frontmatter. `GET /skills`, `GET /skills/view?name=...`, and the `skills` Operator tool (`list`, `search`, `view`). Bundled examples are `operator-safe-file-writes` and `jarvis-vault-research`; private skills can live in `~/.jarvis-tools/skills`.
- `mcp_client.py` — dependency-free MCP client with three transports: local `stdio` (newline-delimited JSON-RPC with a `Content-Length` fallback), remote **Streamable HTTP** (protocol 2025-03-26, JSON or `text/event-stream` replies, `Mcp-Session-Id`) and legacy **HTTP+SSE** (protocol 2024-11-05). Servers are declared in `~/.jarvis-tools/mcp.json`; `stdio` keeps the original shape, remote rows add `transport`, `url`, optional `headers`, `token_env`, `allow_private` and `oauth`:
  ```json
  {"servers": [
    {"name": "files", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    {"name": "search", "transport": "http", "url": "https://mcp.example.com/mcp", "token_env": "SEARCH_MCP_TOKEN"},
    {"name": "legacy", "transport": "sse", "url": "https://mcp.example.com/sse"},
    {"name": "mail", "transport": "http", "url": "https://mcp.example.com/mcp", "oauth": true}
  ]}
  ```
  Public remote endpoints must be HTTPS and resolve only to public addresses; the connection is pinned to a validated public address, redirects are refused so a bearer token cannot be replayed to another origin, and private/LAN targets require an explicit `"allow_private": true` in the user-owned config. OAuth 2.1 uses protected-resource/authorization-server discovery, dynamic client registration when available, PKCE with a loopback redirect, refresh tokens and a 0600 token file beside the config; run `python3 mcp_client.py auth <server>` (add `--no-browser` to print the URL), `logout <server>` or `status`. Token and header values are never returned by `GET /mcp` or the `config()` API. Tool schemas are cached for `JARVIS_MCP_SCHEMA_TTL` seconds (300), failed servers enter exponential cooldown (`JARVIS_MCP_COOLDOWN_SECONDS`, 10), and transient HTTP errors retry at most `JARVIS_MCP_RETRIES` times (2). `GET /mcp` re-reads edited config on every call (removed servers are shut down); `GET /mcp/tools?refresh=1` bypasses the cache; `POST /mcp/call` and the `mcp` Operator tool (`status`, `tools`, `ping`, `call`) remain approval-gated outside Full.
- `web_research.py` — public HTML web search with real titles, snippets and canonical URLs for citation; `GET /research?q=...` and the `web_research` Operator tool. It uses no API key, does not summarize, and returns an error instead of inventing results. The query is capped and the result page is bounded.
- Scheduler v2: schedules now record `max_retries`, `retry_count`, `last_status`, `last_error`, `runs`, `last_job_id` and the real terminal job state. Failed runs use bounded backoff and a desktop notification when `notify-send` exists. The single-job lock still prevents parallel work. The next slot is counted from the slot that became **due** (a long job no longer stretches `every: 1h` into `1h + job duration`); fully missed periods are skipped instead of queueing a catch-up burst, and the tick thread naps to the nearest `next_at` (checked at most each 60 s) and wakes immediately on `stop()`. `POST /agent/schedules/run` with `{id}` and the Studio **Run now** button queue one immediate run without moving the planned slot or consuming a retry; the job wait defaults to 30 minutes and can be tuned with `JARVIS_SCHEDULE_JOB_TIMEOUT` (30 seconds–24 hours).

</details>

<details>
<summary><b>P2: local office, system, apps, organizer and briefing</b></summary>


- `documents.py` — local DOCX/XLSX/PPTX/PDF generation with python-docx, openpyxl, python-pptx and reportlab. Output only under `~/.jarvis-tools/documents`; signatures and sizes are verified. `POST /documents`, `GET /documents`.
- `system_monitor.py` — read-only CPU load, memory, disk, uptime, battery and top processes from `/proc`; `GET /system`.
- `app_identity.py` — reads `.desktop` entries, processes and windows; resolves a name, focuses a window gracefully and closes only with `confirm:true`. Jarvis/Orbit windows are protected. `GET /apps`, `POST /apps`.
- `file_organizer.py` — scans duplicate groups, empty directories and old files; quarantine moves explicit paths to `~/.jarvis-tools/organizer-trash` with a manifest and restore. Nothing is deleted; scans stop at the configured file cap and corrupt manifests are refused instead of crashing a restore. `GET/POST /organizer`.
- `clipboard.py` — reads the X11 clipboard through Tkinter; contents are not logged or persisted. Copying back is done by the browser Clipboard API.
- `briefing.py` — deterministic local daily briefing from system, notes, sessions, schedules, memory and recent documents; `GET /briefing` and `GET /dashboard` (local read-only).
- The Studio has **Briefing**, **System**, **Apps**, **Docs**, **Files**, **Clipboard** and **Selfmod** views in addition to the P1 tabs.
- Remote phone/LAN dashboard, smart-home credentials and avatar/lip-sync are deliberately not enabled: they require a separate security/privacy decision and devices/credentials.

</details>

<details>
<summary><b>Studio UI</b></summary>


`Ctrl+K` opens the command palette (ask, run an Operator task, open Studio tabs, capabilities, view controls). Studio Memory also shows **Suggested memories** with explicit Accept/Reject; Files has **Preview archive** before any move; Docs has document templates and an **Open** action.

The viewer has a **STUDIO** button next to OPERATOR. The panel is a real control surface for the P1 lanes, not a mock:

- **Memory** — add a fact, refresh, recall by query, forget a fact. Values are shown as text, never HTML.
- **Sessions** — recent durable sessions and FTS5 search across past turns.
- **Skills** — list/search `SKILL.md` files and read one in a safe `<pre>`.
- **Web** — public web research with real links, snippets and canonical URLs; price/current questions from chat are researched automatically.
- **MCP** — local and remote server status, tool discovery with a schema cache, a health ping and a confirmation-gated tool call with JSON arguments.
- **Schedule** — add, inspect (including retries and last error) and remove recurring Operator jobs.
- **Briefing** — deterministic daily summary; **System** — live metrics and processes; **Apps** — resolve/focus/confirm-close; **Docs** — generate office files; **Files** — scan/quarantine/restore; **Clipboard** — read local text; **Selfmod** — generate/review a proposal, paste its one-time token, apply, manage learned rules and roll back patches.

The chat answer now carries a visible mode label: `FROM YOUR NOTES` for grounded citations, `GENERAL KNOWLEDGE · NOT FROM YOUR NOTES` for the DeepSeek general lane, or `WEB RESEARCH · PUBLIC SOURCES BELOW` when public web sources were used. The Studio and Operator panels are mutually exclusive so they never cover each other.

The **CAPABILITIES** button (or `?` / `Ctrl+K`) opens a live capability map built from `/capabilities` and `/agent/status`: inventory of notes/general chat, capture, teardown, Operator, voice and every Studio lane, plus the honest limits list. Quick actions can put `remember that ` or `teardown ` into the chat box or open Operator/Studio directly. The dock footer now says **NOTES + GENERAL** instead of implying every answer is note-grounded.

</details>

<details>
<summary><b>Operator agent</b></summary>


Jarvis has a local **Operator** panel for real computer work. A task is sent to a DeepSeek tool-calling model, which can use shell, files, Chromium, native Linux desktop control through cua-driver, HTTP, and named credentials. It reports every action as a step, saves an audit log in the job folder, and shows the latest browser or desktop screenshot. The panel keeps a recent-job history (`~/.jarvis-tools/agent-history.json`, mode 0600) and can OCR the latest screenshot locally with **Read screenshot**. Type the operational request directly in the chat box (for example “otwórz stronę…” or “uruchom…”); the chat server automatically hands imperative tool tasks to the Operator. `/operator <task>`, `operator: <task>` and “użyj operatora i …” still work explicitly. The chat answer says only that it was handed over, not that the work is done, and the Operator keeps its normal approval gates.

The operator is deliberately split into three autonomy modes, selectable in the panel and persisted in `~/.jarvis-tools/agent-mode.json`:

- **Safe** — reads are free; writes, shell, desktop input and credentials ask first.
- **Standard** (default) — shell, files and normal browser/desktop actions run; destructive shell commands (including a destructive **PTY** start or a page-context `eval` that can call the network from an external page), path deletion, credential use and dangerous-looking publish/pay/delete controls ask for **Approve once**. Shell environment overrides the model supplies can no longer name runtime loaders or startup files (`PATH`, `LD_PRELOAD`, `BASH_ENV` and friends are refused).
- **Full** — autonomous; destructive actions and credentials do not prompt. Full is explicit consent for this machine, not the default.

**Stop always wins** for foreground shell commands (the process group is killed), and it ends the job between tool calls. Background shell commands return a PID and log path; stopping the job does not kill an already-detached background process, so the agent reports its PID.

Tools exposed to the model are a fixed registry of **56** names: browser open/read/click/fill/press/scroll, `tabs`, `eval`, `upload`, `download`, `network`; `terminal`, `pty_start`, `pty_send`, `pty_read`, `pty_close`; `read_file`, `write_file`, `restore_file`, `read_pdf`, `ocr_image`, `list_dir`, `search_files`, `delete_path` (recoverable trash; overwrites get a backup); `remember` for indexed vault notes; `desktop` list/capture/click/type/key/scroll/launch/focus/screenshot; `secret` list/type/type_totp/fill_browser/fill_totp; `request_human` for CAPTCHA, SMS/push 2FA or another step only a person can do; `chat_history`; `http_request`; `skill_forge`, `dynamic_skill`, `self_heal`, `learned_rule` for the self-modification lane; `undo_last` for the persistent file undo stack; `memory`, `session_search`, `skills`, `mcp` and `web_research` for P1; `system_monitor`, `app_control`, `organizer`, `document_create`, `clipboard_read` and `briefing` for P2; `delegate` for isolated read-only research subagents (spawn/wait/list/steer/cancel/result); and `finish`.

The PTY lane is the answer to programs that need a terminal: `sudo` (with an interactive password), `ssh`, `npm login`, `python3 -i` and similar. `pty_start` launches a new session in its own process group; `pty_send`, `pty_read` and `pty_close` drive it. Safe mode asks before opening or typing into a PTY; in Standard every `pty_start` command and every `pty_send` line is checked against the destructive-shell rules (`sudo`, absolute `/bin/rm`, `sh -c 'rm -rf …'`, `--recursive`, `shutdown`, …), so an interactive PTY cannot silently reopen the `sudo` bypass. Every PTY is closed when the job ends.

The browser lane now has tabs (`tabs`), JavaScript evaluation (`eval`), file upload (`upload`), download (`download`) and a bounded request/response log (`network`). Script, upload and download ask in Safe mode. In Standard, `eval` calls that use network primitives (`fetch`, `XMLHttpRequest`, `WebSocket`, storage APIs) on an external page also ask, because page-context JavaScript is the one exfiltration channel the approval layer cannot observe. `open_url`/`tabs:new` refuse loopback, private, link-local and carrier-NAT targets (the same SSRF rule as `http_request`), and unresolvable hostnames are simply refused instead of being treated as public. A `request_human` call pauses the job in `awaiting_approval`; approve it after completing CAPTCHA or a push confirmation, and the model resumes. The visible browser is required for that handoff; on this Wayland session headful Chromium silently becomes headless, so use an Xorg session when a human must see the page.

`read_pdf` uses the system `pdftotext`; `ocr_image` reads text from PNG/JPG/BMP/TIFF/WebP/GIF with local Tesseract (`eng`, `pol`, and a few others). OCR is text extraction, not semantic image understanding. The Operator has a fallback ladder for transport/rate-limit/5xx errors and records each fallback as a step. `write_file` makes a timestamped copy in `~/.jarvis-tools/backups` before replacing an existing file; `restore_file` can put that copy back, and `delete_path` moves to `~/.jarvis-tools/trash`. Shell and browser actions outside those file paths are not automatically undoable.

Recurring tasks use `GET /agent/schedules` and `POST /agent/schedules` (`task`, optional `every_seconds` between 60 seconds and 30 days, optional `name`, optional `max_retries` 0–3); run one immediately with `POST /agent/schedules/run` and its `id`, and remove one with `POST /agent/schedules/remove` and its `id`. The schedule file is `~/.jarvis-tools/schedules.json`, mode `0600`. A tick reuses the single-job lock and waits for the real terminal job state. A failed run gets at most `max_retries` bounded retries with backoff, records `last_error` and notifies through `notify-send` when available; it is never run in parallel. No schedule is created unless you add one explicitly.

Set credentials from a terminal, never in chat:

    .venv/bin/python operator_secrets.py set school
    .venv/bin/python operator_secrets.py set-totp school-2fa
    .venv/bin/python operator_secrets.py list

Credentials are stored in the desktop keyring through SecretService; `~/.jarvis-tools/secrets.json` keeps only names and types (mode `0600`). Values are read with a hidden prompt and never printed. At boot the configured DeepSeek key is copied into the broker as `deepseek` if absent; a legacy `openrouter` entry is removed when DeepSeek is the provider, so the agent can use it through an approval-gated HTTP/shell call without putting it in the prompt. If no credential is stored, the operator cannot invent one. Passwords, 2FA codes and card fields are typed through the broker and are not returned to the model. The Chromium profile is `~/.jarvis-tools/agent-profile`; the desktop driver is the pinned cua-driver under `~/.hermes/tools`. A daemon left over from an earlier session can accept the socket while never answering; the bridge detects that failure, stops the stale daemon, removes its socket and starts a fresh one before retrying the desktop call.

Jev (TypeSafe System One) is an optional, decision-only layer: it never answers chat or performs an action. Store a TypeSafe API key under `jev-api-key` (`.venv/bin/python operator_secrets.py set jev-api-key`); Jarvis calls only the official `https://api.typesafe.ai/v1/systemone` contract (`choice`/`score`/`noul`). With no key, a timeout or any unusable answer, mail triage and the router keep their existing rules. `JEV_MODEL` overrides the pinned `jev-1.14.0`.

Endpoints: `POST /agent/run`, `GET /agent/status`, `POST /agent/mode`, `POST /agent/approve`, `POST /agent/stop`, `GET /agent/screenshot`, `GET|POST /agent/schedules`, `POST /agent/schedules/run` and `POST /agent/schedules/remove`. A job is server-side and runs in a background thread; the panel polls status. Native desktop control on Wayland depends on the compositor and cua-driver; this workspace currently reports a Wayland session and the X11 bridge can see no top-level windows, so the agent says so instead of pretending. For full native-window control, log out and choose an Xorg session at the login screen (or grant the desktop portal); shell, files, PTY, PDF and Chromium work regardless.

</details>

<details>
<summary><b>Butler persona and control tags</b></summary>


Edit the single clearly marked PERSONA block near the top of `server.py`: boot greeting, system prompt, dignified fallback, command descriptions, request-authorisation patterns and receipt wording all live there. Public `persona.js` exposes only the greeting, never the full prompt or private configuration. Restart the server after editing the block.

`CONTROL_TAGS` is the only tag registry. The model must return one exact tag without prose; the server allowlists it against the current user's request, runs its registered handler, then issues an actual receipt. Currently supported: counting the real indexed notes and clearing only the current conversation history. Unsupported physical/external actions return an explicit unavailable result, not a pretend success. Missing-note or ungrounded answers move to the general DeepSeek lane with no citations; `[NOT_IN_NOTES]` in an ordinary question is also handled there. Actions and teardown keep the strict tag path, and unknown/unrequested/mixed tags in an action request are rejected. Future capabilities require a real safe handler plus one registry entry; adding a label alone does not create an action.

Short conversational prompts (`say something`, `hello`, `how are you`, `who are you`, `what can you do`, thanks) are answered locally before retrieval and before any provider call. They return no source nodes and cannot be turned into a fabricated citation. Everything else remains an evidence question.

Every action now carries both its legacy receipt `status` (`completed`, `unavailable`, `cancelled`) and a plain public `outcome` (`done`, `unverified`, `failed`, `ask`, `started`). The UI shows the outcome, not just the internal status. A completed capture has `outcome: "done"` only after its file, graph entry and live retrieval readback have all been verified.

Live persona/action verification: `.venv/bin/python verify_persona.py`, with real outputs saved to `artifacts/persona-verification.json`. The UI displays execution receipt ids and outcomes separately from the butler's spoken reply.

</details>

<details>
<summary><b>Remember that: live captures</b></summary>


Say or type `remember that the finish window should be 900 milliseconds`. The prefix is routed locally to `POST /remember`, not to the model. The server saves a private markdown file under `~/notes/captures/`, with a readable title from the first words, today's date, and a related-note wikilink. No speech or model service is needed to persist a capture.

ONE server door: `Application.capture_note(text, request_id=None)` in `server.py`. This writes and verifies the file, appends the next positional id to `viewer/graph-data.js`, uses the same `build.graph_from_notes` link rules as the indexer, and verifies the graph-backed live search index before issuing a receipt. Existing ids are never reordered. `/chat` rereads that index for every question, so the new note is immediately eligible evidence without running build.py. Runtime write/publication failures roll back the new file/index where possible and return a spoken error; uncertain failures explicitly say that a file may remain. Captures are serialised, and a repeated Idempotency-Key replays the same capture rather than making another star.

ONE viewer door: `galaxy.addNote(capture)` in `viewer/app.js`. Future note-producing features must use it for birth at the best related note's position, graph/search/legend updates, a brief glow pulse, and camera flight/selection. Reduced motion skips the pulse. The complete graph snapshot also lets a stale tab catch up without renumbering nodes. Successful captures confirm in one butler line; failures are displayed and spoken through the same mute-protected speech function. Questions arriving during a capture wait for its indexing to finish. The `?mute=1` testing rule still applies.

Manual acceptance (refresh once to load this feature, then do not reload):

1. Enable the mic with English (UK) selected, then say: “remember that the finish window should be 900 milliseconds”. Typing it and pressing Ask works too.
2. Watch the count increase by one and a new star pulse at its related note, then watch the camera fly to the selected capture. Hear: “Filed and indexed, sir; this one is committed to more than conversation.” The receipt and source chip should appear.
3. Immediately ask: “How long should the finish window be?” Expect 900 milliseconds with the new capture as a clickable source, without any rebuild or reload.
4. The actual file is under captures, not just in chat history; refreshing later preserves it.

`.venv/bin/python verify_capture.py` exercises real file writes, real WebGL birth/pulse/fly, both input routes, an immediate live model answer, and a deliberately failed graph publication with a spoken error, using an isolated fixture vault so it does not pre-create your manual example. Speech/recognition are event doubles, not a physical microphone/speaker check. Evidence: `artifacts/capture-verification.json`, `artifacts/capture-birth.png` and `artifacts/capture-selected.png`.

</details>

<details>
<summary><b>Reverse-engineering bay (REA)</b></summary>


REA lives outside the project at `~/.jarvis-tools/rea`; the repo stays free of its dependencies. It is installed from the official npm package `rea-agents`, whose repository was verified before install:

    npm view rea-agents repository.url
    # git+https://github.com/morluto/rea.git

Exact commands used (version current at install time):

    mkdir -p ~/.jarvis-tools/rea
    cd ~/.jarvis-tools/rea
    npm init -y
    npm install rea-agents@6.7.0 --save-exact --ignore-scripts

The version is pinned exactly in `package.json`; nothing in Jarvis resolves `latest` at runtime. REA requires Node `^22.19.0 || ^24.11.0 || >=26.0.0`. The bay finds Node on `PATH` or in common install locations (including `~/.hermes/tools/node-*`), validates the version, and invokes REA directly as `node <rea-root>/node_modules/rea-agents/scripts/rea.mjs COMMAND ... --json`, so a server started without the user's shell PATH still works.

`teardown.py` is Python-standard-library only and is soft-imported by `server.py`; a missing or broken bay leaves Jarvis booting normally.

- `GET /teardown/diag` returns `ready`, installed and pinned REA versions, Node version/support, Chrome discovery (Google Chrome, Chromium or official Chrome for Testing; macOS and Windows paths included), and a plain-English `problems` list.
- `POST /teardown` accepts `{command, target?, arguments?, timeout?}`. It validates the command token, appends `--json`, runs without a shell with a bounded timeout, kills the whole process group on timeout, and returns parsed JSON plus an execution receipt (exit code, duration). Missing prerequisites return HTTP 503 with a single in-character line naming the exact install commands; nothing crashes.
- Commands still require explicit `command`/`target` from the caller; Jarvis does not guess what to tear down.

The environment has no system Google Chrome, so diagnosis uses the official `Google Chrome for Testing 156.0.8078.4` binary already installed by Playwright at `~/.cache/ms-playwright/...`. The report labels the kind honestly; install Google Chrome if you want the branded browser lane.

</details>

<details>
<summary><b>Ephemeral teardown browser</b></summary>


REA never launches its own browser for these jobs; it connects to a Chrome that Jarvis owns. `browser_bay.py` is standard-library only.

For every job it creates a brand-new profile at `~/.jarvis-tools/rea/profiles/JOB_ID` (mode `0700`) and launches Chrome with:

    --user-data-dir=<fresh profile>
    --remote-debugging-port=9333
    --remote-debugging-address=127.0.0.1
    --no-first-run --no-default-browser-check --disable-extensions
    --window-size=1280,820
    <site URL>

Your everyday Chrome profile, cookies and logins are never touched. A fresh profile also prevents cached responses from masking a site's real weight.

- It polls `http://127.0.0.1:9333/json/version` for at most 25 seconds, finds the page target for the requested host (accepting `www.` and redirects), waits for `document.readyState === "complete"`, then waits 2.5 seconds for intro animations.
- `browser_bay.CDPWebSocket` is a minimal RFC 6455 client: handshake validation, masked client frames, 16/64-bit payload lengths, fragmented replies, ping/pong and close. It exposes only `Runtime.evaluate` for read-only facts and `Input.dispatchMouseEvent` `mouseWheel` for scrolling; no `scrollTo`.
- Close runs in a `finally`-style path: terminate the process group, kill every process still referencing the profile path, wait for port 9333 to be released, delete the profile, then verify. The result includes a cleanup receipt; a failure raises `BrowserCleanupError` rather than claiming success.
- `POST /teardown/browser` accepts `{url, job_id?, headless?, scroll?}` and performs the one-shot open/observe/scroll/close. `headless: true` adds `--headless=new` so tests never pop a window. One job at a time owns the port; a second request gets HTTP 409.
- `teardown.with_browser(url, callback)` keeps the browser alive for a REA `capture-browser-scenario` using `browser: {mode: "connect", cdp_endpoint: "http://127.0.0.1:9333", target_id: ...}`, then closes it.

On this Ubuntu host AppArmor restricts unprivileged user namespaces, so Chrome is launched with `--no-sandbox`; the facts report `"sandbox": false`. On hosts where the sandbox is available it is left enabled.

Run `python3 verify_browser.py` for the live proof: headless public page, title and load seconds, a wheel scroll, then zero processes referencing the profile, no profile folder, and port 9333 closed.

</details>

<details>
<summary><b>Evidence capture (REA + Jarvis)</b></summary>


`python3 verify_evidence.py` runs the five-lane evidence pass against a public 3D site (default `https://www.monogrid.com/`) and prints an attributed digest.

- **REA** lists the target, runs `inspect-web-page` for 7 seconds while Jarvis sends 16 wheel steps one second in, analyses the bundle for file-load edges, routes and shader/uniform inferences, then captures a screenshot after Jarvis has wheel-scrolled back to the top.
- **Jarvis** owns the ephemeral Chrome, all wheel input, `performance.getEntriesByType('resource')` (every entry and origin, with sizes where the browser exposes them), fingerprint scanning of REA-captured source, and PNG decoding/saving.
- Every digest line is prefixed `[REA]` or `[Jarvis]`; stack findings say `[REA (source capture) / Jarvis]` because the source was captured by REA and scanned by Jarvis.
- Asset kinds are 3D models, compressed textures, video, audio, fonts, WebAssembly, scripts, styles, images, data/API, document and other, with zero counts shown. Cross-origin entries without `Timing-Allow-Origin` expose no size in the Performance API; the full per-entry log is saved in `assets.json`, and the digest says so.
- The fingerprint table lives in `evidence_bay.py` as `FINGERPRINT_PATTERNS`, ordered 3D engine, animation, smooth scroll, visual effects, compression, build tools. Other licence banners are reported separately.
- Artifacts go to `artifacts/evidence/JOB_ID/`: `inspect.json`, `analyze.json`, `assets.json`, `screenshot.png`, `digest.json`, `digest.txt`.
- `POST /teardown/browser` remains the one-shot browser lane; evidence capture uses `teardown.browser_job` directly so the browser can stay alive across REA calls and is closed in a `finally`-style path.

</details>

<details>
<summary><b>Teardown: read, hear, keep</b></summary>


Type or say `teardown <url> [question]` in the viewer. The server runs the five-lane evidence capture headless, compresses it to an attributed plain-text digest under `JARVIS_REA_DIGEST_CHARS` (40,000 by default), and makes exactly one model call with a `JARVIS_REA_DIGEST_TOKENS` budget (12,000 by default; the DeepSeek adapter still clamps output to the provider limit). The model must return `LABEL`, `SPOKEN`, `SUMMARY` and `---NOTE---`; the parser rejects missing sections, a wrong host, or a note without a verdict.

REA resource ceilings are tunable in the environment (read once at import; restart the service after a change): `JARVIS_REA_TIMEOUT` (command seconds, default 1800, hard max 21600), `JARVIS_REA_TIMEOUT_MAX`, `JARVIS_REA_STDOUT_MB` (default 128, max 512), `JARVIS_REA_STDERR_KB` (default 1024), `JARVIS_REA_INSPECT_MS` (default 15000), `JARVIS_REA_ANALYZE_MS` (default 5000), `JARVIS_REA_SCROLL_STEPS` (default 32), `JARVIS_REA_WHEEL_DELTA` (default 700), `JARVIS_REA_SOURCE_MB` (per fallback asset, default 32), `JARVIS_REA_FALLBACK_FETCHES` (default 24), `JARVIS_REA_DIGEST_CHARS` and `JARVIS_REA_DIGEST_TOKENS`; the browser timings are `JARVIS_REA_ENDPOINT_TIMEOUT` (45 s), `JARVIS_REA_LOAD_TIMEOUT` (90 s), `JARVIS_REA_TARGET_TIMEOUT` (20 s), `JARVIS_REA_INTRO_WAIT` (2.5 s) and `JARVIS_REA_SETTLE_SECONDS` (20 s). These are resource ceilings only: URL validation, SSRF guards, the one-teardown lock, approvals and the Chromium sandbox policy are not configurable. `GET /teardown/diag` exposes the active values under `limits`.

The note is written to `NOTES/captures/teardowns/HOST-DATE.md`, with the snapshot at `NOTES/captures/teardowns/assets/HOST-DATE.png` embedded in the note and a deterministic `## Evidence` section containing the stack, totals and REA evidence ids. The REA concept note at `NOTES/concepts/REA.md` is created on the first teardown and linked with `[[REA]]`.

Indexing uses `Application.total_recall_index`, the Total Recall graph door: it preserves every existing positional id, appends notes in order, computes links with the shared `build.graph_from_notes` engine, writes atomically and verifies the graph. Births are returned in order (REA first if new, teardown second); the viewer calls its one `addNote` door for each, so the camera flies to the teardown last. `SPOKEN` is passed to the same mute-aware speaker.

One teardown runs at a time. A second request receives exactly `I'm already taking one apart, sir.` (`POST /teardown/run` returns 409). The full flow is verified by `verify_teardown_ui.py`.

</details>

<details>
<summary><b>Voice teardowns and the live card</b></summary>


The voice lane recognizes only sentences that name a site or say `this site` / `this page`: `reverse engineer igloo dot inc`, `tear down linear.app`, `how does stripe.com do that`, and `what is example.com built with`. Spoken `dot`, `slash`, and `colon` become `.`, `/`, and `:`; `localhost` is accepted. `tear down the old shed` and `how should I reverse engineer my pricing` deliberately fall through to the brain. A sentence with no address is answered by the brain with exactly `[TEARDOWN:SITE|QUESTION]`; the server starts the job and returns a short spoken acknowledgement. `this` means the front Chrome tab on macOS via `osascript`, and is refused if that tab is Jarvis; elsewhere Jarvis asks for the name.

`POST /teardown/run` now starts a background job and acknowledges immediately. The card polls `/teardown/status?job_id=...`; `POST /teardown/cancel` cancels between evidence lanes and closes the browser cleanly. `GET /teardown/last` finds the newest note on disk after a restart. `GET /teardown/note` and `GET /teardown/snapshot` feed the reader, which offers Open in Obsidian and Close and strips the note's front matter so no file paths appear on screen.

The card sits top-left beside the atlas. It shows the site and a `via REA` chip, then the eight real steps: opening a clean browser, waiting for load, REA watching while Jarvis scrolls, REA reading the code, taking a snapshot, listing everything loaded, identifying the stack, and writing the teardown. When done it folds to `Taken apart in N s`, then the snapshot, up to ten stack chips, totals, and **Read the full teardown**. It never auto-hides and measures the atlas, note panel and answer dock, shrinking and dropping the snapshot before it could overlap them.

Voice commands: `show me the last teardown`, `open the full teardown`, `close the teardown`, `cancel the teardown`. The live acceptance run is:

    .venv/bin/python verify_teardown_ui.py --run https://www.monogrid.com/

It runs twelve sentences through the real routes in a `?mute=1` tab at 1440x900, runs one real teardown, and saves `artifacts/teardown-panel-1440x900.png`, `artifacts/teardown-panel-1440x900-live.png`, `artifacts/teardown-page-1440x900-live.png`, `artifacts/teardown-reader-1440x900.png` and `artifacts/teardown-ui-verification.json`. The live card drops the snapshot only when the answer dock leaves insufficient height; closing the answer reveals the complete card.

</details>

<details>
<summary><b>Proof before the camera</b></summary>


`python3 teardown_offline.py` is fast and browser-free: it runs the real voice address parser for `igloo dot inc`, `stripe.com slash pricing`, `localhost:5001`, `make it pop` (nothing), and `wikipedia.org` (first letter preserved); fingerprints a synthetic source as Three.js r165 and GSAP 3.12.5; and proves every nonblank digest line starts with `[REA]` or `[Jarvis]`.

`python3 verify_teardown_drill.py --url https://www.monogrid.com/` snapshots `viewer/graph-data.js`, `artifacts/teardown-episodes.jsonl`, the teardowns folder and the REA concept note, runs one real headless teardown, checks the eight panel steps, note sections, spoken line, births, elapsed time and episode record, then restores the snapshot exactly and removes the test note. It also asserts both note and snapshot endpoints refuse `../config.json`, kills a browser to prove crash cleanup, and checks no investigation Chrome, profile folder or port 9333 is left. The drill report is `artifacts/teardown-drill.json`.

The episode log is `artifacts/teardown-episodes.jsonl`: one JSON line per completed, failed or cancelled job, with no local paths. It is optional to the note and is restored byte-for-byte by the drill.

The current vault is indexed (262 notes at the time of this pass); the teardowns folder has no notes and `NOTES/concepts/REA.md` is absent. The first on-camera teardown therefore creates both the REA concept and the first teardown note. Previous development teardowns were archived under `artifacts/pre-camera-archive-20261020/`.

The preflight gate is now 43 checks. `capabilities` proves the running `/capabilities` manifest matches the prompt registry and contains no stale blanket denial; `routing` proves a disk question reaches the Operator, a destructive chat request asks first and starts nothing, a capability question is answered from the live registry, and the public path view never invents a home subdirectory; `retrieval` proves the live FTS5 index covers every graph node with the keyword fallback inactive; `voice` proves the Edge voice options, output picker, idle input meter and push-to-talk controls are live; `tts` makes a real Edge synthesis and checks the MPEG frame; `agent` verifies the operator mode/tool registry and launches a real headless browser to read the local viewer; `remember` also proves the live receipt publishes `outcome=done`. The final checks are `kit` (ready, pinned REA installed), `offline` (the three fast proofs above), `chrome_clean` (no investigation Chrome, profile or CDP listener), plus the isolated `webbackends`, `context`, `checkpoints`, `ocr` and `planfiles` lanes. The card check uses a disposable `preflight.local` note that is removed after the run, so preflight works before the first real teardown. The `hardening` check proves the Operator's file reader refuses credentials (while still reading its own artifacts), `redact()` masks the value of any secret-named environment variable, the third identical tool call in a row returns `LOOP_GUARD`, and the `archive_ops` module is live in the registry.

</details>

<details>
<summary><b>Live preflight — completion gate</b></summary>


Run `.venv/bin/python preflight.py` before declaring a change complete, and include its exact final `N pass, N fail, N warn` line in the handoff. A non-zero exit means a live chain failed: fix its cause and rerun; passing regression tests is not a substitute. This is the required workflow for subsequent changes and Part Two checks.

The ordered `CHECKS` registry in `preflight.py` is the extension point. It currently checks the live viewer, graph plus native WebGL rendering, a real UI /chat answer, the live capability manifest and prompt agreement, the FTS5 retrieval index coverage, authenticated key metadata, the exact configured model via the Models API plus a real minimal inference, a real UI /remember/file/immediate recall/cleanup chain with an explicit `outcome=done`, byte identity of all browser-served local assets and running backend fingerprints, config isolation, native ?mute=1 speech refusal after a trusted click, live Edge voice options/output-voice/push-to-talk/input-meter controls, a real Edge synthesis with an MPEG header check, a real headless browser-agent page read, a live headless teardown browser that proves its profile and port are gone, a full five-lane evidence capture with attribution, the Total Recall teardown index/birth contract, a live 1440x900 teardown card/reader with twelve voice-route classifications, the pinned REA kit, the browser-free offline proofs, and final investigation-Chrome cleanup. No fixture vault, intercepted HTTP response, replacement speech engine or provider stub is used by preflight.

The test capture is written into the REAL vault with a unique disposable marker, read back from disk, cited by the next real model answer, then removed from disk and the live graph. Cleanup uses `/preflight/cleanup`, which accepts only proof of the owned disposable final node; it refuses user notes and never renumbers later user nodes. Run preflight while capture input is idle. If safe cleanup cannot be proved, the check fails and retains `artifacts/preflight-pending.json` for recovery rather than deleting unrelated data. A single-instance lock prevents overlapping harness runs.

`/health` reports code fingerprints, not credentials, so a stale server process cannot pass merely because edited files exist on disk. `viewer/persona.js` is a generated public asset produced at server startup from the persona block. Static assets, including graph-data.js, are validated and served byte-for-byte from disk, never reformatted in transit. The two exact-version CDN scripts carry SHA-384 integrity hashes and `crossorigin="anonymous"`, so a compromised or altered CDN response is rejected by the browser rather than executed.

Preflight makes real DeepSeek inference calls and therefore consumes a small amount of account credit. The key is never printed or included in its JSON report. The browser's native audio output is safety-muted, while the application's own mute guard must independently return false and leave the native speech queue empty. This checks the actual runtime branch, not speaker hardware quality.

Latest report: `artifacts/preflight.json`. The script uses `.venv` automatically if the system Python lacks its dependencies. Fresh development setup:

    .venv/bin/python -m pip install -r requirements-dev.txt
    .venv/bin/python -m playwright install chromium
    .venv/bin/python preflight.py

Future checks should append an id/label/method entry to `CHECKS` and implement their real live chain in this same harness, preserving all existing checks and cleanup guarantees.

</details>

<details>
<summary><b>Regression tests</b></summary>


    .venv/bin/python -m unittest discover -s tests -v

The JS contract tests locate Node through `JARVIS_NODE`, `PATH`, or the common `~/.hermes/tools/node-*` install and skip cleanly when it is absent. The static gate is `scripts/lint.py`, a pyflakes pass that honours per-line `# noqa` availability probes (`import tkinter  # noqa`), and `scripts/check.sh` runs it before the unit suite. Both must be clean before a handoff; preflight remains the live acceptance layer above them. `scripts/prune_artifacts.py` is a dry-run-first retention pass for `artifacts/evidence` and `artifacts/agent` (default: keep 25 newest and 7 days).

Module layout: `studio_routes.py` owns the P2 GET/POST branches (the handler delegates to it in the original route order), `errors.py` holds the shared `AppError`, and `vector_store_base.py` owns the SQLite float32 store that both `note_vectors.py` and `memory_vectors.py` subclass (corrupt-file quarantine, model-change tripwire, exact cosine scan). New runtime files are listed in `RUNTIME_SOURCES`, so `/health` fingerprints them and the served-files check notices a stale process. The systemd unit starts `scripts/boot_server.py`: if a staged self-modification left a pending patch that cannot be imported, the guard restores the timestamped backup before `server.py` runs, so a broken patch cannot become a two-second restart loop.

Browser verification uses the optional development dependency Playwright, installed in this environment. See `artifacts/verification.json` and `artifacts/` screenshots after the acceptance run. Mocked provider tests exercise request shape/retries/session behavior; they are not represented as successful live model calls.

</details>

## License

MIT — see [LICENSE](LICENSE).
