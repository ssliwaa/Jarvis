# Voice acceptance plan

Open http://127.0.0.1:4700/ in a browser with Web Speech support (Chrome/Edge recommended), then hard reload. Edge TTS uses the free Microsoft endpoint through the pinned `edge-tts` dependency; the browser voice remains available as a fallback. No paid speech-service key or account is used.

Use headphones for the interruption test: the microphone intentionally stays enabled during spoken answers so it can hear “stop” and “wait”; loudspeaker feedback can otherwise be mistaken for your speech. Browser speech recognition may use the browser vendor's online service. This is not a guarantee of offline/on-device recognition.

## 1. First interaction and British voice

1. Load the page and do not click anything.
2. Expected: silence. No automatic microphone prompt.
3. Click “Pause orbit” once (or another non-navigation control).
4. Expected: the first line is exactly “Hello, sir.” and the small status shows Speaking while it plays. It must not have spoken before the click. The same greeting is visible from page load; the real graph-derived note count stays on screen and is not added to the spoken greeting.
5. If an en-GB system/browser voice exists it is preferred; otherwise an English/default voice is used. An initially empty voice list does not delay the first-click call. An installation with no working synthesis voices cannot produce audio; failures are shown without breaking typing.

## 2. Type an answer request

1. Type “Co moje notatki mówią o zasadzie 80/20?” and press Enter or Ask.
2. Expected: Thinking while /chat is pending, then the answer appears and is spoken. With the default British output voice the answer is English — the model translates Polish note content — so the voice never reads Polish text; choosing Marek or Zofia keeps the answer Polish. A question outside the notes (for example “Co to jest skrócenie Lorenza?”) must also come back in English: if a fallback lane returns Polish anyway, the server translates that answer once before replying, so the British voice still reads English. The panel shows the growing streamed text, and with an Edge voice the first complete sentence is spoken while the rest is still being generated; the remainder follows without a new full-answer synthesis. Status changes to Speaking and then Ready (or Listening when the microphone is on).
3. Citation indexes and markdown emphasis are not read aloud as markup.

## 3. Microphone and deliberate mid-sentence pause

1. The small recognition-language selector should already show “Polski” on a Polish system (it follows `navigator.language`); select it manually if the system locale is not Polish. Reload the page and confirm the explicit choice survives the reload.
2. Click the microphone icon and allow microphone access when asked.
3. Expected: the button stays highlighted, its accessible label becomes “Stop listening”, and status shows Listening once capture starts.
4. Say “Co moje notatki mówią”, deliberately pause for about 0.6 seconds, then say “o treningu biegowym?”
5. Stop speaking for at least 0.9 seconds after the final recognized phrase.
6. Expected: the transcript/input contains the entire combined question. No question is sent during the short pause. Exactly one /chat request is sent for the full sentence, followed by Thinking and a displayed/spoken answer.
7. To inspect the exact payload/count, use the browser Network panel filtered to /chat. A genuine pause longer than FINISH_MS can end a thought by design; this setting is one constant, FINISH_MS = 900, near the top of viewer/voice.js.
8. Click the microphone again to stop it. Expected: its highlight turns off and pending, unsent fragments are discarded.

## 4. Immediate interrupts

1. Keep the mic on, select English (UK), and ask a question.
2. While the answer is speaking, say just “stop”.
3. Expected: output stops as soon as the browser recognizes the word, including an interim result; there is no 900 ms wait. No /chat request containing “stop” is made. Any buffered question is discarded.
4. Ask another question and say “wait” while Thinking. Expected: the browser request is canceled, the UI says “Answer interrupted.”, and a late response must not restart speech. The server may finish an already-started provider call internally.
5. The Stop button performs the same interruption without needing microphone recognition. The mic remains armed for the next question until you toggle it off.

## 5. Self-echo guard

1. Keep the mic on and ask a question whose answer is a full sentence.
2. Let the answer play through the speakers without headphones. Expected: the page may transcribe part of its own voice, but it must not submit that transcript as a new user question or speak a second answer.
3. While the answer is speaking, say a genuinely different short question. Expected: it is still accepted after the normal 900 ms finish window.
4. While the answer is speaking, say “stop”. Expected: the immediate interrupt still works; the guard does not swallow a short command.
5. Immediately after the answer ends, wait through the 2.5 s echo tail. Expected: a repeated fragment of the answer is ignored during the tail; a new question afterwards is accepted.

The guard is lexical, not acoustic: the browser Web Speech API supplies transcripts, not raw microphone audio. The automated `echo` scenario covers own-sentence echo, a different question, the post-speech tail and short-user interruption. In the desktop window the same guard runs on the local `/voice/transcribe` result; record a take while an answer is playing and confirm its transcript is dropped instead of submitted. The recorder also requests echo cancellation, noise suppression and automatic gain control from the microphone.

## 6. Silent tab — mandatory mute check

1. Open http://127.0.0.1:4700/?mute=1 in a separate tab.
2. Click controls. Expected: no welcome is spoken.
3. Type the question from test 2. Expected: the answer appears, status includes “Muted by URL”, and absolutely nothing is spoken.
4. Enable the mic and ask the combined question from test 3. Expected: recognition and /chat still work, but the answer is silent.
5. Switch tabs/background it. Expected: no audio. Backgrounding also turns off capture and cancels current speech. Every speech path passes through the same mute-checked speak function.

## 7. Denied/unsupported microphone

Deny microphone permission, or use a browser without either webkitSpeechRecognition or SpeechRecognition. Expected: a clear permission/availability message, no stuck Listening state, no crash, and typing still works. The microphone button is disabled when the API itself is absent.

## 7b. Silent or muted microphone

1. Mute the headset microphone (hardware button or system capture volume) but keep it armed.
2. In the desktop window, tap the microphone, stay silent for about two seconds, then tap again.
3. Expected: the status says “The recording was silent — check the microphone and its mute button”. No empty question is sent, and the input meter stays flat. Unmute and repeat: the same take is now transcribed.
4. Speak very quietly instead of muting. Expected: the quiet take is lifted automatically and still transcribed; `/voice/status` reports an `audio_seconds` and `level_dbfs` for the last successful take.

## 8. Edge TTS and browser fallback

1. Open the voice toolbar. “Auto — Edge British (Ryan)” is the default. The picker also lists Thomas, Sonia and Libby in British English, Marek and Zofia in Polish, a browser Auto option, and the installed browser voices. Pick a voice, reload, and confirm it is still selected.
2. Ask a question with an answer. The answer should be spoken by the selected Edge neural voice, not the system espeak voice. The Edge request goes to `/tts`; it is not a browser speechSynthesis call.
3. Select “Browser — Auto (English UK)” and ask again. The browser voice should replace Edge; this proves the offline fallback without uninstalling anything.
4. With Edge selected, start a question and press Stop while the audio is playing. Playback must stop immediately and the status must leave Speaking. Ask another question; the late first answer must not play over it.
5. With Edge selected, disconnect the network or temporarily stop the server. Ask again. Jarvis should fall back to the browser voice and say that the Edge voice was unavailable rather than staying silent.
6. Arm the microphone. The IN meter should move with your voice; stop the microphone and confirm it returns to its idle hidden state.
7. Focus the page (not an input) and hold Ctrl+Space. Speak a question, release the keys, and confirm the phrase is delivered after the normal finish window. Confirm Ctrl+Space while typing in the question field does not start the microphone. In the desktop window, switch to another application, press Ctrl+Shift+Space, speak, and press it again: recording starts and the question is sent without focusing Jarvis. Repeat with the recognition language set to Polski and English (UK) and confirm the local transcript follows the picker.
8. In a `?mute=1` tab, repeat the voice picker, meter and acknowledgment checks: the meter may move, but no Edge request is made and nothing is spoken.

Edge sends only the spoken sentence to Microsoft and requires network access. It does not receive the vault, conversation history, paths or credentials. The browser route remains available for privacy or offline use. This is not the native Mark stack: local wake word, raw-PCM acoustic echo cancellation, OS audio-device selection, lip-sync and local Whisper/Piper models are not included.

## Extension contract

Add local commands through galaxy.voice.routes, an ordered array of {pattern: RegExp, handler(text, match, voice)}. A matching route runs before the brain. Optional immediate: true routes are also recognized immediately from interim recognition results. The built-in stop/wait interrupt route stays first. Use voice.speak for any command response so ?mute=1 and activation cannot be bypassed.

## Automated evidence

- `.venv/bin/python -m unittest discover -s tests -v`: the full suite covers deterministic fake-clock speech/recognition cases, persona rules, receipt-backed control tags and live captures; use its execution summary for the current test count. `tests/test_stt.py` additionally covers silent-take rejection, quiet-take gain, silence trimming, repeated-sentence collapse and the small-model preference; `tests/test_voice.js` covers the locale-derived and persisted recognition language plus the spoken-text sanitizer.
- `node tests/test_edge_voice.js`: offline Edge client test with a fake `/tts` response and fake audio element; proves the request shape, MP3 blob-to-audio path, mute no-request rule, browser fallback on a failed Edge response, and that a cancelled request cannot play late audio. It is also invoked from `tests/test_voice.py`, so the normal suite gate runs it.
- `.venv/bin/python verify_voice.py`: actual Chromium page with explicit speech/recognition and /chat doubles; tests first click, en-GB selection, two finals separated by 600 ms, no dispatch at 899 ms, one combined dispatch at 900 ms, interim stop/wait, route extension, late-response suppression, silent tab and responsive controls.
- Report: artifacts/voice-verification.json. Screenshots: artifacts/voice-desktop.png and artifacts/voice-mobile.png.
- These automated tests do not claim to have heard a physical speaker or transcribed a physical microphone. Perform the manual steps above for that hardware/browser verification. The headless test browser exposes the APIs but has no installed speech voices.
