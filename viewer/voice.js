'use strict';

// One finish window for all recognition phrases; never dispatch on the first final.
const FINISH_MS = 900;
// A spoken answer can arrive back through the microphone after its onend event.
const ECHO_TAIL_MS = 2500;
const ECHO_MIN_TOKENS = 3;
const EDGE_DEFAULT_VOICE = 'en-GB-RyanNeural';
// The recognition language is about the microphone, not the reply. A Polish
// system should hear Polish on first launch, and an explicit choice must survive
// a reload; otherwise every session silently falls back to English (UK).
const LANGUAGE_KEY = 'galaxy.lang';
const LANGUAGE_CHOICES = ['en-GB', 'pl-PL'];
const EDGE_VOICES = [
  { id: 'en-GB-RyanNeural', label: 'Ryan — British male (Studio HD, crystal clear)' },
  { id: 'en_GB-jarvis-distilled', label: 'J.A.R.V.I.S. — F5-TTS Distilled (Clear & Natural)' },
  { id: 'en-GB-ThomasNeural', label: 'Thomas — British male (Studio HD)' },
  { id: 'en_GB-jarvis-medium', label: 'J.A.R.V.I.S. — Paul Bettany (Movie rip)' },
  { id: 'en-GB-SoniaNeural', label: 'Sonia — British female' },
  { id: 'en-GB-LibbyNeural', label: 'Libby — British female' },
  { id: 'pl-PL-MarekNeural', label: 'Marek — Polish male' },
  { id: 'pl-PL-ZofiaNeural', label: 'Zofia — Polish female' },
];

(() => {
  window.createGalaxyVoice = ({ submit, interrupt = () => {} }) => {
    const $ = id => document.getElementById(id);
    const synthesis = window.speechSynthesis;
    let unlocked = false;

    let currentUtterance = null;
    let thinking = false;
    let speaking = false;
    let listening = false;
    let detail = '';
    const Recognition = window.webkitSpeechRecognition || window.SpeechRecognition;
    const recognition = Recognition ? new Recognition() : null;
    let microphoneWanted = false;
    // Electron has SpeechRecognition but no Google speech backend, so every session
    // dies with a `network` error. When the server exposes /voice/transcribe we record
    // with MediaRecorder and let whisper.cpp do the work on this machine.
    let serverStt = false;
    let recording = false;
    let startingRecording = false;
    let recordingGeneration = 0;
    let recorderSession = null;
    let recordTimer = null;
    let wake = null, wakeEnabled = false, wakeRecording = false, wakeRearmTimer = null;
    let pendingStop = false;
    // A push-to-talk release that beats getUserMedia still owes the user a take:
    // the device opened late, so the recorder keeps this minimum window instead
    // of being stopped in the same tick (which encoded audio-less blobs).
    const MIN_CAPTURE_MS = 900;
    let pttReleased = false;
    let pttFlushTimer = null;
    let starting = false;
    let transcribeToken = 0;
    let transcribeAbort = null;
    // Prefer the microphone's own echo canceller; the lexical guard below stays
    // as the second line of defence when it is unavailable.
    // autoGainControl is deliberately OFF for takes: Chromium's AGC writes
    // capture gain back to the device and, after a loud take, silently pulls
    // the source volume down (measured: a raised PipeWire source fell back
    // between takes), so the next recordings arrive near-silent and the gate
    // reports "too weak" — or amplifies room noise into junk. Echo
    // cancellation stays off as well on this lane: push-to-talk starts the
    // take, and the lexical echo guard still runs on the transcript.
    const RECORD_AUDIO = {
      audio: { echoCancellation: false, noiseSuppression: true, autoGainControl: false },
    };
    // Speech recording needs more level than the system's 100% mic cap gives on
    // some devices (measured −66 dBFS peaks on this host's headset). The boost
    // is applied in the recording graph, before the encoder, so the uploaded
    // blob matches the meter. A value in dB lives in localStorage as
    // 'galaxy.mic-boost' (e.g. '0' disables, '20' lifts hard); the default is
    // +12 dB, roughly doubling-to-quadrupling the observed peaks.
    function micBoostFactor() {
      let decibels = 12;
      try {
        const stored = window.localStorage?.getItem?.('galaxy.mic-boost');
        if (stored !== null && stored !== undefined && String(stored).trim() !== '') {
          decibels = Number(stored);
        }
      } catch (_) { /* private mode; keep the default */ }
      if (!Number.isFinite(decibels)) decibels = 12;
      decibels = Math.max(0, Math.min(30, decibels));
      return Math.pow(10, decibels / 20);
    }
    // One boost graph for the whole session — a fresh AudioContext per take
    // adds churn to every push-to-talk and Chromium discards suspended
    // contexts' output silence, which looked exactly like a mic loss after a
    // few recordings. The graph stays open; each take plugs its stream in and
    // unplugs it again.
    let boostGraph = null;
    function boostGraphFor(stream) {
      const AudioCtor = window.AudioContext || window.webkitAudioContext;
      if (typeof AudioCtor !== 'function') return null;
      try {
        if (!boostGraph || boostGraph.context.state === 'closed') {
          boostGraph = null;
          const context = new AudioCtor();
          const gain = context.createGain();
          gain.gain.value = micBoostFactor();
          const tapped = context.createMediaStreamDestination();
          if (typeof context.createDynamicsCompressor === 'function') {
            const compressor = context.createDynamicsCompressor();
            if (compressor.threshold) compressor.threshold.value = -6;
            if (compressor.knee) compressor.knee.value = 6;
            if (compressor.ratio) compressor.ratio.value = 12;
            if (compressor.attack) compressor.attack.value = 0.003;
            if (compressor.release) compressor.release.value = 0.15;
            gain.connect(compressor);
            compressor.connect(tapped);
          } else {
            gain.connect(tapped);
          }
          boostGraph = { context, gain, tapped };
        }
        if (boostGraph.context.state === 'suspended') {
          boostGraph.context.resume().catch(() => { /* resumed later or failed */ });
        }
        // The gain is read fresh for every take, so a localStorage change
        // applies without reloading the page.
        boostGraph.gain.gain.value = micBoostFactor();
        const source = boostGraph.context.createMediaStreamSource(stream);
        source.connect(boostGraph.gain);
        return { context: boostGraph.context, source,
                 stream: boostGraph.tapped.stream };
      } catch (_) {
        return null;   // plain passthrough below
      }
    }
    function detachBoost(session) {
      if (session?.boost?.source) {
        try { session.boost.source.disconnect(); } catch (_) { /* already gone */ }
      }
      if (session?.boost) session.boost.source = null;
    }
    let finishTimer = null;
    let restartTimer = null;
    let fragments = [];
    let interimText = '';
    let lastSpokenText = '';
    let lastSpokenAt = 0;
    let echoTimer = null;
    let edgeAudio = null;
    let edgeUrl = null;
    let edgeAbort = null;
    let edgeToken = 0;
    let speechSession = null;
    // Early speech during /chat/stream: complete sentences are spoken while
    // the model is still writing. The final result then appends only its tail.
    let streamFed = '';
    let streamHeld = false;
    let streamBlocked = false;
    let streamActive = false;
    let pttHeld = false;
    let meterStream = null;   // stream this module opened and must stop
    let meterSource = null;   // stream being analysed (owned or borrowed)
    let meterContext = null;
    let meterFrame = null;
    const finalizedResults = new Set();
    // Extension point: append { pattern: /.../, handler(text, match, voice) }.
    // Only explicit immediate routes bypass FINISH_MS (including interim results).
    const voiceRoutes = [{
      id: 'site',
      resolve: parseSiteCommand,
      handler: (sentence, match) => {
        if (!window.galaxy) return false;
        if (match.site === 'this') return window.galaxy.teardownCurrent(match.question);
        return window.galaxy.runTeardown(match.site, match.question);
      }
    }, {
      id: 'last',
      pattern: /^(?:show|open)\s+(?:me\s+)?(?:the\s+)?(?:last|latest|most\s+recent)\s+teardown[.!?]*$/i,
      handler: () => Boolean(window.galaxy?.showLastTeardown?.())
    }, {
      id: 'open',
      pattern: /^(?:open|show)\s+(?:me\s+)?(?:the\s+)?(?:full|whole)\s+teardown(?:\s+note)?[.!?]*$/i,
      handler: () => Boolean(window.galaxy?.openTeardownReader?.())
    }, {
      id: 'close',
      pattern: /^(?:close|hide|dismiss)\s+(?:the\s+)?teardown(?:\s+(?:panel|reader))?[.!?]*$/i,
      handler: () => Boolean(window.galaxy?.closeTeardown?.())
    }, {
      id: 'cancel',
      pattern: /^(?:cancel|stop)\s+(?:the\s+)?teardown(?:\s+(?:job|run))?[.!?]*$/i,
      handler: () => Boolean(window.galaxy?.cancelTeardown?.())
    }, {
      id: 'agent',
      pattern: /^(?:take\s+over|use|control|drive)\s+(?:my|the)\s+(?:computer|browser|screen|pc)\b[\s,:-]*(.*)$/i,
      handler: sentence => {
        if (!window.galaxyAgent?.start) return false;
        window.galaxyAgent.start(sentence);
        return true;
      }
    }, {
      id: 'stop',
      pattern: /^(?:stop|wait|pause|czekaj|poczekaj)[.!?,\s]*$/i,
      immediate: true,
      handler: () => {
        clearFinish();
        fragments = [];
        interimText = '';
        $('voice-transcript').textContent = '';
        stopSpeaking();
        disableWake();
        interrupt();
        detail = 'Interrupted';
        updateStatus();
        return true;
      }
    }];
    const WAKE_RE = /^(?:hey|hej|hi|ok|okay|halo)\s+jarvis[\s,.:;!?-]*/i;
    let dictateNext = false;

    function speechAddress(text) {
      let value = String(text || '').trim().replace(/[.!?;,]+\s*$/, '');
      value = value.replace(/\b(?:dot|punkt)\b/gi, '.')
        .replace(/\b(?:slash|szlauf)\b/gi, '/')
        .replace(/\bcolon\b/gi, ':')
        .replace(/\s*([./:])\s*/g, '$1')
        .replace(/\s+/g, ' ');
      const address = value.match(/(?:https?:\/\/)?(?:localhost(?::\d{1,5})?|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d{1,5})?(?:\/[^\s?#]*)?/i);
      if (!address) return null;
      let candidate = address[0].replace(/[.,!?;:]+$/, '');
      if (!candidate || candidate.length > 2048) return null;
      const port = candidate.match(/:(\d{1,5})(?:\/|$)/);
      if (port && (Number(port[1]) < 1 || Number(port[1]) > 65535)) return null;
      return candidate;
    }

    function parseSiteCommand(text) {
      const sentence = String(text || '').trim().replace(/[.!?]+\s*$/, '');
      let candidate = null;
      let match = sentence.match(/^(?:reverse\s+engineer|reverse-engineer|tear\s*down|teardown)\s+(?:the\s+)?(.+)$/i);
      if (match) candidate = match[1];
      if (candidate === null) {
        match = sentence.match(/^how\s+(?:does|do|is|are)\s+(.+?)\s+(?:do|work|works|build|built|achieve|pull|make|render)\b.*$/i);
        if (match) candidate = match[1];
      }
      if (candidate === null) {
        match = sentence.match(/^what\s+is\s+(.+?)\s+built\s+with\b.*$/i);
        if (match) candidate = match[1];
      }
      if (candidate === null) return null;
      const clean = candidate.trim().replace(/^["']|["']$/g, '');
      const deictic = /^(?:this|current)\s+(?:site|page|tab)$/i.test(clean);
      if (deictic) return { site: 'this', question: sentence };
      const site = speechAddress(clean);
      return site ? { site, question: sentence } : null;
    }

    function speechTokens(text) {
      return String(text || '').toLocaleLowerCase()
        .replace(/[^\p{L}\p{N}]+/gu, ' ')
        .split(' ')
        .filter(Boolean);
    }

    // The browser gives us the transcript, not the microphone waveform, so this
    // is a lexical guard rather than Mark's acoustic echo canceller. It catches
    // the failure that matters: the assistant's own sentence arriving as input.
    function isEcho(text) {
      if (!lastSpokenText) return false;
      const age = Date.now() - lastSpokenAt;
      if (age < 0 || age > ECHO_TAIL_MS) return false;
      const candidate = speechTokens(text);
      const spoken = speechTokens(lastSpokenText);
      if (!candidate.length || !spoken.length) return false;
      const candidateText = candidate.join(' ');
      const spokenText = spoken.join(' ');
      if (candidate.length >= 2 && candidateText === spokenText) return true;
      if (candidate.length >= ECHO_MIN_TOKENS && spokenText.includes(candidateText)) return true;
      if (candidate.length < ECHO_MIN_TOKENS) return false;
      const bag = new Map();
      spoken.forEach(token => bag.set(token, (bag.get(token) || 0) + 1));
      let overlap = 0;
      candidate.forEach(token => {
        const left = bag.get(token) || 0;
        if (left) {
          overlap += 1;
          bag.set(token, left - 1);
        }
      });
      return overlap / candidate.length >= 0.7;
    }

    function availableVoices() {
      try {
        return synthesis && typeof synthesis.getVoices === 'function' ? synthesis.getVoices() : [];
      } catch (_) {
        return [];
      }
    }

    function storedVoice() {
      try {
        return String(window.localStorage?.getItem('galaxy.voice') || '');
      } catch (_) {
        return '';
      }
    }

    function rememberVoice(name) {
      try {
        if (name) window.localStorage?.setItem('galaxy.voice', name);
        else window.localStorage?.removeItem('galaxy.voice');
      } catch (_) {}
    }

    function storedLanguage() {
      try {
        const value = String(window.localStorage?.getItem(LANGUAGE_KEY) || '');
        return LANGUAGE_CHOICES.includes(value) ? value : '';
      } catch (_) {
        return '';
      }
    }

    function rememberLanguage(value) {
      try {
        if (LANGUAGE_CHOICES.includes(value)) window.localStorage?.setItem(LANGUAGE_KEY, value);
      } catch (_) {}
    }

    function preferredLanguage() {
      const stored = storedLanguage();
      if (stored) return stored;
      const locale = String(window.navigator?.language || '').toLowerCase();
      return locale.startsWith('pl') ? 'pl-PL' : 'en-GB';
    }

    function usableVoices() {
      // speech-dispatcher can expose thousands of espeak-ng variants named
      // "English (Great Britain)+Adam". They are not useful as a picker list;
      // keep the base voices and drop duplicate name/language pairs.
      const seen = new Set();
      return availableVoices().filter(voice => {
        const name = String(voice.name || '').trim();
        const lang = String(voice.lang || '').trim();
        if (!name) return false;
        if (/\+/.test(name) && /espeak(?:-ng)?/i.test(name)) return false;
        const key = `${name}\u0000${lang}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    }

    function populateVoices() {
      const select = $('voice-output');
      if (!select || typeof select.replaceChildren !== 'function' || typeof document.createElement !== 'function') return;
      const voices = usableVoices();
      // The select already has a default option before it is populated, so
      // select.value always masked a saved voice and reload reverted to Ryan.
      const current = storedVoice() || select.value;
      const values = [];
      select.replaceChildren();
      const addOption = (value, text) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = text;
        select.append(option);
        values.push(value);
      };
      addOption('edge:auto', 'Auto — Edge British (Ryan)');
      for (const voice of EDGE_VOICES) addOption(`edge:${voice.id}`, `Edge — ${voice.label}`);
      addOption('browser:auto', 'Browser — Auto (English UK)');
      [...voices].sort((a, b) => String(a.name).localeCompare(String(b.name))).forEach(voice => {
        addOption(`browser:${voice.name}`, `Browser — ${voice.name} — ${voice.lang || 'unknown'}`);
      });
      const valid = values.includes(current);
      if (!valid && storedVoice()) rememberVoice('');
      select.value = valid ? current : 'edge:auto';
    }

    function voiceChoice() {
      return $('voice-output')?.value || storedVoice() || 'edge:auto';
    }

    function browserVoiceName() {
      const choice = voiceChoice();
      if (choice.startsWith('browser:')) return choice.slice(8);
      if (choice.startsWith('edge:')) return '';
      return choice;
    }

    function edgeVoiceId() {
      const choice = voiceChoice();
      if (!choice.startsWith('edge:')) return null;
      return choice === 'edge:auto' ? EDGE_DEFAULT_VOICE : choice.slice(5);
    }

    // The spoken voice decides the reply language. The British voice cannot
    // pronounce Polish, so an English output voice asks the model for an
    // English answer (it translates whatever Polish note content matters);
    // only an explicitly Polish voice keeps Polish answers.
    function replyLanguage() {
      const choice = voiceChoice();
      if (choice.startsWith('edge:')) {
        const id = choice === 'edge:auto' ? EDGE_DEFAULT_VOICE : choice.slice(5);
        return /^pl(?:[-_]|$)/i.test(String(id)) ? 'pl' : 'en';
      }
      const name = choice.startsWith('browser:') ? choice.slice(8) : choice;
      if (!name || name === 'auto') return 'en';  // Auto prefers British English
      const voice = usableVoices().find(item => String(item.name || '') === name);
      return /^pl(?:[-_]|$)/i.test(String(voice?.lang || '')) ? 'pl' : 'en';
    }

    function chooseVoice() {
      const voices = usableVoices();
      if (!voices.length) return null;
      const requested = browserVoiceName();
      const exact = voices.find(voice => voice.name === requested);
      if (exact) return exact;
      // Hearing language is not speaking language. Jarvis answers in British
      // English by default; tying Auto to the recognition selector made a
      // Polish microphone read English answers in Polish phonetics.
      const wanted = 'en-gb';
      const base = 'en';
      return voices.find(voice => String(voice.lang || '').toLowerCase().replace('_', '-') === wanted)
        || voices.find(voice => String(voice.lang || '').toLowerCase().replace('_', '-').split('-')[0] === base)
        || voices.find(voice => voice.default)
        || voices[0];
    }

    function setMeter(value) {
      const node = $('mic-level');
      if (!node) return;
      node.hidden = false;
      if (node.style?.setProperty) {
        node.style.setProperty('--mic-level', String(Math.max(0.03, Math.min(1, value))));
      }
    }

    function stopMeter() {
      if (meterFrame !== null && typeof window.cancelAnimationFrame === 'function') {
        window.cancelAnimationFrame(meterFrame);
      }
      meterFrame = null;
      if (meterStream) {
        try { meterStream.getTracks().forEach(track => track.stop()); } catch (_) {}
        meterStream = null;
      }
      // A borrowed stream belongs to the recorder; closing the analyser must not
      // stop its tracks. The recorder stops them after its final chunk.
      meterSource = null;
      if (meterContext) {
        try { meterContext.close(); } catch (_) {}
        meterContext = null;
      }
      const node = $('mic-level');
      if (node) {
        node.hidden = true;
        node.style?.setProperty?.('--mic-level', '0.03');
      }
    }

    async function startMeter(borrowed = null) {
      const nav = window.navigator || {};
      const Audio = window.AudioContext || window.webkitAudioContext;
      if (meterSource || typeof Audio !== 'function'
          || typeof window.requestAnimationFrame !== 'function') return;
      if (!borrowed && !nav.mediaDevices?.getUserMedia) return;
      try {
        let stream = borrowed;
        if (!stream) {
          stream = await nav.mediaDevices.getUserMedia(RECORD_AUDIO);
          if (!microphoneWanted) {
            stream.getTracks().forEach(track => track.stop());
            return;
          }
          meterStream = stream;
        }
        if (!stream?.getAudioTracks?.().length) return;
        meterSource = stream;
        meterContext = new Audio();
        const source = meterContext.createMediaStreamSource(stream);
        const analyser = meterContext.createAnalyser();
        analyser.fftSize = 256;
        source.connect(analyser);
        const samples = new Uint8Array(analyser.fftSize);
        const draw = () => {
          if (!meterSource || !meterContext) return;
          analyser.getByteTimeDomainData(samples);
          let total = 0;
          for (const sample of samples) {
            const centred = (sample - 128) / 128;
            total += centred * centred;
          }
          setMeter(Math.sqrt(total / samples.length) * 2.2);
          meterFrame = window.requestAnimationFrame(draw);
        };
        draw();
      } catch (_) {
        stopMeter();
      }
    }

    function updateStatus() {
      const phases = [];
      if (listening) phases.push('Listening');
      if (thinking) phases.push('Thinking');
      if (speaking) phases.push('Speaking');
      const status = phases.join(' · ') || 'Ready';
      $('voice-status').textContent = detail ? `${status} · ${detail}` : status;
      $('voice-status').dataset.state = speaking ? 'speaking' : thinking ? 'thinking' : listening ? 'listening' : 'ready';
      $('mic-button').setAttribute('aria-pressed', String(microphoneWanted));
      $('mic-button').setAttribute('aria-label', microphoneWanted ? 'Stop listening' : 'Start listening');
    }

    function clearEchoTimer() {
      if (echoTimer !== null && typeof clearInterval === 'function') clearInterval(echoTimer);
      echoTimer = null;
    }

    function startEchoRefresh() {
      clearEchoTimer();
      if (typeof window.setInterval === 'function') {
        echoTimer = window.setInterval(() => {
          if (speaking) lastSpokenAt = Date.now();
        }, 1200);
      }
    }

    function releaseEdgeAudio() {
      if (edgeAudio) {
        try {
          edgeAudio.pause();
          edgeAudio.removeAttribute('src');
          edgeAudio.load();
        } catch (_) {}
        edgeAudio = null;
      }
      if (edgeUrl && typeof URL !== 'undefined' && typeof URL.revokeObjectURL === 'function') {
        try { URL.revokeObjectURL(edgeUrl); } catch (_) {}
      }
      edgeUrl = null;
    }

    function cancelSpeech() {
      edgeToken += 1;
      speechSession = null;
      if (edgeAbort) {
        try { edgeAbort.abort(); } catch (_) {}
        edgeAbort = null;
      }
      releaseEdgeAudio();
      currentUtterance = null;
      clearEchoTimer();

      speaking = false;
      if (synthesis) synthesis.cancel();
    }

    function stopSpeaking() {
      cancelSpeech();
      streamActive = false;
      streamFed = '';
      streamHeld = false;
      streamBlocked = false;
      updateStatus();
    }

    function speakBrowser(plain) {
      if (!synthesis || typeof window.SpeechSynthesisUtterance !== 'function') {
        detail = 'Speech output unavailable';
        updateStatus();
        return false;
      }
      lastSpokenText = plain;
      lastSpokenAt = Date.now();
      detail = '';
      const utterance = new window.SpeechSynthesisUtterance(plain);
      const preferred = chooseVoice();
      utterance.voice = preferred || null;
      utterance.lang = preferred ? preferred.lang : 'en-GB';
      utterance.rate = 1;
      currentUtterance = utterance;
      speaking = true;
      startEchoRefresh();
      utterance.onstart = () => { if (currentUtterance === utterance) { speaking = true; updateStatus(); } };
      utterance.onboundary = () => {
        if (currentUtterance === utterance) lastSpokenAt = Date.now();
      };
      utterance.onend = () => {
        if (currentUtterance !== utterance) return;
        clearEchoTimer();
        currentUtterance = null;
        speaking = false;
        lastSpokenAt = Date.now();
        updateStatus();
      };
      utterance.onerror = event => {
        if (currentUtterance !== utterance) return;
        clearEchoTimer();
        currentUtterance = null;
        speaking = false;
        lastSpokenAt = Date.now();
        detail = event.error === 'not-allowed' ? 'Audio blocked — click and ask again' : 'Speech output unavailable';
        updateStatus();
      };
      updateStatus();
      try { synthesis.speak(utterance); }
      catch (_) { utterance.onerror({ error: 'unavailable' }); return false; }
      return true;
    }

    function sanitizeSpeech(text) {
      // Strip what should never be read aloud: code fences, markdown links
      // (keep their label), citation markers such as [0] or [W1], raw URLs and
      // emphasis characters.
      return String(text || '')
        .replace(/```[\s\S]*?```/g, ' ')
        .replace(/\[([^\]]{1,80})\]\((?:https?:\/\/|\/)[^)]*\)/g, '$1')
        .replace(/\[\s*[A-Z]?\d+\s*\]/gi, '')
        .replace(/\bhttps?:\/\/\S+/gi, 'link')
        .replace(/[*_`#]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    }

    // Sentence-sized chunks start the voice far sooner than one request for the
    // whole answer (measured: 116 chars ≈ 2.7 s versus 843 chars ≈ 8.6 s).
    function splitSpeech(text) {
      const parts = String(text || '').match(/[^.!?…]+[.!?…]+(?:["'”’)\]]+)?|[^.!?…]+$/g) || [];
      const chunks = [];
      for (const raw of parts) {
        let piece = raw.trim();
        while (piece.length > 400) {
          let cut = Math.max(piece.lastIndexOf(', ', 400), piece.lastIndexOf(' ', 400));
          if (cut < 80) cut = 400;
          chunks.push(piece.slice(0, cut + 1).trim());
          piece = piece.slice(cut + 1).trim();
        }
        if (piece) chunks.push(piece);
      }
      return chunks;
    }

    function stableSentencePrefix(text) {
      const value = String(text || '');
      const boundary = /[.!?…](?:["'”’)\]]*)(?=\s|$)/g;
      let end = 0;
      let match;
      while ((match = boundary.exec(value)) !== null) end = match.index + match[0].length;
      return end ? value.slice(0, end) : '';
    }

    const POLISH_LETTERS = /[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/g;
    const POLISH_WORDS = new Set(
      'się nie jest oraz który która które przez dla tego tej są był była było można '
      .concat('tylko jeszcze już bardzo także więc ponieważ aby lub albo czy że od po przy ')
      .concat('między jednak jeśli kiedy gdzie dlatego').split(' '));
    function looksPolishClient(text) {
      const value = String(text || '');
      const letters = (value.match(POLISH_LETTERS) || []).length;
      const words = value.toLowerCase().match(/[a-ząćęłńóśźż]+/g) || [];
      const hits = words.filter(word => POLISH_WORDS.has(word)).length;
      return letters >= 2 || hits >= 3;
    }

    function mutedByUrl() {
      return new URLSearchParams(window.location.search).getAll('mute').includes('1');
    }

    function newEdgeSession(choice) {
      cancelSpeech();
      const session = {
        token: edgeToken,
        controller: typeof AbortController === 'function' ? new AbortController() : null,
        voice: choice === 'edge:auto' ? EDGE_DEFAULT_VOICE : choice.slice(5),
        queue: [],
        playing: false,
        spoken: '',
      };
      edgeAbort = session.controller;
      speechSession = session;
      speaking = true;
      detail = '';
      startEchoRefresh();
      updateStatus();
      return session;
    }

    function edgeBlob(session, entry) {
      if (!entry.promise) {
        let timer = null;
        const timeout = new Promise((_, reject) => {
          if (typeof setTimeout === 'function') {
            timer = setTimeout(() => reject(new Error('edge timeout')), 20000);
          }
        });
        entry.promise = Promise.race([
          fetch('/tts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: entry.text, voice: session.voice }),
            signal: session.controller ? session.controller.signal : undefined,
          }).then(response => {
            if (!response.ok) throw new Error('edge status ' + response.status);
            return response.blob();
          }).then(blob => {
            if (!blob || !blob.size) throw new Error('empty edge audio');
            return blob;
          }),
          timeout,
        ]).finally(() => {
          if (timer !== null && typeof clearTimeout === 'function') clearTimeout(timer);
        });
      }
      return entry.promise;
    }

    function enqueueEdge(session, chunks) {
      if (!session || session.token !== edgeToken) return;
      for (const text of chunks) {
        if (!text) continue;
        session.queue.push({ text, promise: null });
        session.spoken = session.spoken ? `${session.spoken} ${text}` : text;
      }
      if (session.playing && session.queue.length) {
        edgeBlob(session, session.queue[session.queue.length - 1]).catch(() => {});
      }
      if (!session.playing) playEdgeQueue(session);
    }

    function edgeFallback(session) {
      if (!session || session.token !== edgeToken) return false;
      const remaining = session.queue.map(entry => entry.text).join(' ').trim();
      // Invalidate every late fetch of this session, then let the browser voice
      // finish what Edge could not speak.
      edgeToken += 1;
      session.token = -1;
      if (speechSession === session) speechSession = null;
      if (session.controller) {
        try { session.controller.abort(); } catch (_) {}
      }
      if (edgeAbort === session.controller) edgeAbort = null;
      session.playing = false;
      session.queue = [];
      releaseEdgeAudio();
      clearEchoTimer();
      speaking = false;
      detail = 'Edge voice unavailable; using the browser voice';
      // Early-speech mode must not start a fresh Edge session for later chunks.
      if (streamActive) streamBlocked = true;
      if (remaining) return speakBrowser(remaining);
      updateStatus();
      return false;
    }

    function playEdgeQueue(session) {
      if (!session || session.token !== edgeToken || session.playing) return;
      const entry = session.queue[0];
      if (!entry) {
        clearEchoTimer();
        speaking = false;
        lastSpokenAt = Date.now();
        if (speechSession === session) speechSession = null;
        updateStatus();
        return;
      }
      session.playing = true;
      // Request this sentence first, then download the next one while it plays.
      const current = edgeBlob(session, entry);
      if (session.queue[1]) edgeBlob(session, session.queue[1]).catch(() => {});
      current.then(blob => {
        if (session.token !== edgeToken) return;
        if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function'
            || typeof window.Audio !== 'function') throw new Error('audio unavailable');
        const url = URL.createObjectURL(blob);
        const audio = new window.Audio(url);
        edgeUrl = url;
        edgeAudio = audio;
        let finished = false;
        const advance = () => {
          if (finished || edgeAudio !== audio) return;
          finished = true;
          releaseEdgeAudio();
          session.playing = false;
          lastSpokenAt = Date.now();
          playEdgeQueue(session);
        };
        audio.onended = advance;
        audio.onerror = () => {
          if (finished || session.token !== edgeToken) return;
          finished = true;
          releaseEdgeAudio();
          session.playing = false;
          // The entry is removed only after play() is invoked; put it back so
          // the browser fallback does not silently drop this sentence.
          session.queue.unshift(entry);
          edgeFallback(session);
        };
        audio.ontimeupdate = () => { if (edgeAudio === audio) lastSpokenAt = Date.now(); };
        lastSpokenText = session.spoken;
        lastSpokenAt = Date.now();
        if (typeof audio.play !== 'function') throw new Error('audio play unavailable');
        const playback = audio.play();
        session.queue.shift();
        if (playback && typeof playback.catch === 'function') {
          playback.catch(() => {
            if (finished || session.token !== edgeToken) return;
            finished = true;
            releaseEdgeAudio();
            session.playing = false;
            session.queue.unshift(entry);
            edgeFallback(session);
          });
        }
      }).catch(() => {
        if (session.token !== edgeToken) return;
        session.playing = false;
        edgeFallback(session);
      });
    }

    function startSpeech(plain) {
      lastSpokenText = plain;
      lastSpokenAt = Date.now();
      const choice = voiceChoice();
      if (choice.startsWith('edge:') && typeof window.fetch === 'function'
          && typeof window.Audio === 'function') {
        const chunks = splitSpeech(plain);
        if (!chunks.length) return false;
        const session = newEdgeSession(choice);
        enqueueEdge(session, chunks);
        return true;
      }
      return speakBrowser(plain);
    }

    // Feed the growing streamed answer. Only complete sentences are spoken, and
    // a Polish answer bound for an English voice is held for the server's
    // translation instead of being read aloud.
    function streamSpeech(accumulated) {
      if (mutedByUrl() || !unlocked || streamHeld || streamBlocked) return false;
      const choice = voiceChoice();
      if (!choice.startsWith('edge:') || typeof window.fetch !== 'function'
          || typeof window.Audio !== 'function') return false;
      const plain = sanitizeSpeech(accumulated);
      const stable = stableSentencePrefix(plain);
      if (!stable || stable.length <= streamFed.length) return false;
      if (replyLanguage() === 'en' && looksPolishClient(stable)) {
        streamHeld = true;
        return false;
      }
      const fresh = stable.slice(streamFed.length).trim();
      streamFed = stable;
      if (!fresh) return false;
      streamActive = true;
      if (!speechSession) newEdgeSession(choice);
      enqueueEdge(speechSession, splitSpeech(fresh));
      return true;
    }

    // Reconcile the streamed speech with the authoritative final answer.
    function finishSpeech(text) {
      const plain = sanitizeSpeech(text);
      const wasActive = streamActive;
      const fed = streamFed;
      const blocked = streamBlocked;
      streamActive = false;
      streamFed = '';
      streamHeld = false;
      streamBlocked = false;
      if (!plain) return false;
      if (wasActive && fed && plain.startsWith(fed)) {
        const fresh = plain.slice(fed.length).trim();
        if (!fresh) return true;
        if (blocked) return speakBrowser(fresh);
        if (speechSession) {
          enqueueEdge(speechSession, splitSpeech(fresh));
          return true;
        }
        return speak(fresh);
      }
      if (wasActive && fed) {
        // The final answer was truncated or rewritten; the already-spoken
        // stream is authoritative and must not be repeated or cut off.
        return true;
      }
      return speak(text);
    }

    // The ONLY entry point for whole speeches. Every path obeys tab mute + gesture.
    function speak(text) {
      if (mutedByUrl()) {
        stopSpeaking();
        detail = 'Muted by URL';
        updateStatus();
        return false;
      }
      const plain = sanitizeSpeech(text);
      if (!plain) return false;
      if (!unlocked) return false;
      stopSpeaking();
      return startSpeech(plain);
    }

    document.addEventListener('click', event => {
      if (unlocked || event.isTrusted === false) return;
      unlocked = true;
      // Stay in the original click stack, even when getVoices() is initially empty.
      speak(window.GALAXY_PERSONA?.greeting || '');
    }, { capture: true });

    function clearFinish() {
      clearTimeout(finishTimer);
      finishTimer = null;
    }

    function showTranscript() {
      $('voice-transcript').textContent = [...fragments, interimText].filter(Boolean).join(' ');
      $('question').value = $('voice-transcript').textContent.slice(0, 4000);
    }

    function dispatch(text) {
      let sentence = String(text || '').trim();
      if (!sentence) return false;
      if (WAKE_RE.test(sentence)) {
        sentence = sentence.replace(WAKE_RE, '').trim();
        if (!sentence) {
          stopSpeaking();
          interrupt();
          detail = 'Listening — go ahead, sir';
          updateStatus();
          return true;
        }
      }
      if (dictateNext) {
        dictateNext = false;
        if (typeof fetch === 'function') {
          fetch('/voice/dictate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: sentence }),
          }).catch(() => {});
        }
        detail = 'Dictated to active window';
        updateStatus();
        return true;
      }
      for (const route of voiceRoutes) {
        const match = matchRoute(route, sentence);
        if (match) return route.handler(sentence, match, controller);
      }
      // The spoken voice decides the reply language, never the microphone:
      // an English voice earns an English answer (the British voice cannot
      // pronounce Polish), while a Polish voice keeps the default reply.
      return submit(sentence, replyLanguage());
    }

    function matchRoute(route, text) {
      if (typeof route.resolve === 'function') return route.resolve(text);
      route.pattern.lastIndex = 0;
      return route.pattern.exec(text);
    }

    function inspectSentence(text) {
      const sentence = String(text || '').trim();
      for (const route of voiceRoutes) {
        const match = matchRoute(route, sentence);
        if (match) {
          const result = { triggered: true, route: route.id || 'unknown' };
          if (match.site) result.site = match.site;
          if (match.question) result.question = match.question;
          return result;
        }
      }
      return { triggered: false, route: null };
    }

    function scheduleFinish() {
      clearFinish();
      if (pttReleased) { flushNow(); return; }
      if (!fragments.length || interimText) return;
      finishTimer = setTimeout(() => {
        finishTimer = null;
        const sentence = fragments.join(' ').trim();
        fragments = [];
        if (sentence) dispatch(sentence);
      }, FINISH_MS);
    }

    function startRecognition() {
      if (!recognition || !microphoneWanted || starting || listening || document.hidden) return;
      try { starting = true; recognition.start(); }
      catch (_) {
        starting = false;
        microphoneWanted = false;
        detail = 'Microphone could not start — click to retry';
        updateStatus();
      }
    }

    function flushNow(reason) {
      clearFinish();
      clearTimeout(pttFlushTimer);
      pttFlushTimer = null;
      const sentence = [...fragments, interimText].filter(Boolean).join(' ').trim();
      fragments = [];
      interimText = '';
      listening = false;
      microphoneWanted = false;
      pttReleased = false;
      try { if (recognition) recognition.abort(); } catch (_) { /* already closed */ }
      stopMeter();
      if (sentence) {
        detail = '';
        updateStatus();
        dispatch(sentence);
      } else {
        detail = reason || 'Nothing was heard — hold Ctrl+Space, speak, then release';
        updateStatus();
      }
    }

    async function startServerRecording() {
      if (wakeEnabled && wake?.active) {
        await wake.stop();
        scheduleWake(8000);
      }
      if (startingRecording) return false;
      if (recording) { stopServerRecording(); return true; }
      pendingStop = false;
      if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder !== 'function') {
        detail = 'This build cannot record audio; typing still works';
        updateStatus();
        return false;
      }
      const generation = ++recordingGeneration;
      // Claim the new take before awaiting the microphone: otherwise an older
      // transcript arriving during getUserMedia still matches transcribeToken
      // and is dispatched as if it belonged to this recording.
      const takeToken = ++transcribeToken;
      if (transcribeAbort) {
        try { transcribeAbort.abort(); } catch (_) { /* already finished */ }
        transcribeAbort = null;
      }
      startingRecording = true;
      let opened = null;
      try {
        const stream = await navigator.mediaDevices.getUserMedia(RECORD_AUDIO);
        opened = stream;
        if (!startingRecording || generation !== recordingGeneration) {
          // A second press cancelled this attempt while the microphone opened.
          stream.getTracks().forEach(track => track.stop());
          return false;
        }
        // A new recording supersedes an older one, including its pending upload.
        if (recorderSession) {
          const previous = recorderSession;
          recorderSession = null;
          try { previous.recorder?.stop(); } catch (_) { /* already closed */ }
          try { previous.stream?.getTracks?.().forEach(track => track.stop()); } catch (_) { /* gone */ }
          detachBoost(previous);
        }
        const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
          ? 'audio/webm;codecs=opus' : 'audio/webm';
        // A quiet microphone (a distant headset boom, a laptop mic at 100%)
        // otherwise hands whisper a take that needs heavy rescue later. The
        // persistent boost graph lifts the signal *before* encoding: the
        // recorder, the uploaded blob and the meter all show the boosted
        // level. A plain passthrough keeps working when the graph fails.
        let recordStream = stream;
        const plugged = boostGraphFor(stream);
        if (plugged) {
          recordStream = plugged.stream;
        }
        const session = {
          chunks: [],
          startedAt: 0,
          discard: false,
          cancelled: false,
          token: takeToken,
          recorder: null,
          stream,
          boost: plugged,
        };
        const recorder = new MediaRecorder(recordStream, { mimeType });
        session.recorder = recorder;
        recorderSession = session;
        recorder.ondataavailable = event => { if (event.data && event.data.size) session.chunks.push(event.data); };
        recorder.onstop = () => { finishServerRecording(session); };
        recorder.start();
        session.startedAt = Date.now();  // start counting only after the recorder is actually running
        opened = null;  // the session owns the stream from here on
        startingRecording = false;
        recording = true;
        microphoneWanted = true;
        listening = true;
        detail = 'Recording — tap again to stop';
        // Reuse the recorder's graph. A second getUserMedia capture on PipeWire
        // can take a different/gated device and make the recorder look silent;
        // the boosted stream also shows the level the transcriber will hear.
        startMeter(recordStream);
        updateStatus();
        clearTimeout(recordTimer);
        recordTimer = setTimeout(stopServerRecording, 60000);
        // The user may release Ctrl+Space before the microphone resolves; without
        // this the recorder would keep running and nothing would ever be sent.
        if (pendingStop) {
          // The key was released while the device was still opening. Stopping
          // in this tick encoded a header with no audio (the 110-byte uploads),
          // so keep a minimum window first: the tail of what was said still
          // reaches the transcriber instead of an empty blob.
          pendingStop = false;
          const wait = Math.max(0, MIN_CAPTURE_MS - (Date.now() - session.startedAt));
          clearTimeout(session.minStopTimer);
          session.minStopTimer = setTimeout(() => {
            if (recorderSession === session) stopServerRecording();
          }, wait);
          return true;
        }
        return true;
      } catch (error) {
        if (opened) {
          try { opened.getTracks().forEach(track => track.stop()); } catch (_) { /* already gone */ }
        }
        if (generation !== recordingGeneration) return false;
        startingRecording = false;
        microphoneWanted = false;
        listening = false;
        detail = error?.name === 'NotAllowedError'
          ? 'Microphone blocked — allow it for Jarvis in system settings'
          : 'No microphone found';
        updateStatus();
        return false;
      }
    }

    async function wakeRecord() {
      if (speaking) { stopSpeaking(); interrupt(); }
      if (recording || startingRecording) return false;
      const started = await startServerRecording();
      if (started) {
        detail = 'Wake detected — speak now (6 seconds)';
        clearTimeout(recordTimer);
        recordTimer = setTimeout(stopServerRecording, 6000);
        updateStatus();
      }
      return started;
    }

    function showWakeState(on) {
      const button = $('wake-toggle');
      if (!button) return;
      button.setAttribute('aria-pressed', String(on));
      button.textContent = `Hey Jarvis: ${on ? 'on' : 'off'}`;
    }

    function disableWake() {
      wakeEnabled = false;
      if (wakeRecording) { wakeRecording = false; stopServerRecording(true); }
      clearTimeout(wakeRearmTimer);
      wakeRearmTimer = null;
      wake?.stop();
      showWakeState(false);
    }

    function scheduleWake(delay = 1000) {
      clearTimeout(wakeRearmTimer);
      wakeRearmTimer = setTimeout(armWake, delay);
    }

    async function armWake() {
      if (!wakeEnabled || !wake) return;
      if (listening || startingRecording || thinking || speaking) { scheduleWake(); return; }
      try {
        await wake.start();
        if (!wakeEnabled) await wake.stop();
      } catch (_) {
        disableWake();
        detail = 'Wake-word microphone or detector unavailable';
        updateStatus();
      }
    }

    if (typeof window.createJarvisWake === 'function') {
      wake = window.createJarvisWake({
        async onWake() {
          if (!wakeEnabled) return;
          wakeRecording = true;
          if (await wakeRecord()) scheduleWake(8000);
          else { wakeRecording = false; disableWake(); }
        },
        onError(message) { disableWake(); detail = message; updateStatus(); },
      });
      $('wake-toggle')?.addEventListener('click', () => {
        if (wakeEnabled) { disableWake(); return; }
        wakeEnabled = true;
        showWakeState(true);
        armWake();
      });
      window.addEventListener?.('pagehide', disableWake);
    }

    function stopServerRecording(discard = false) {
      wakeRecording = false;
      if (startingRecording) {
        // The microphone is still opening. Discarding the start here threw away
        // every push-to-talk take whose key release beat getUserMedia: the user
        // spoke, released, and nothing was ever recorded (the icon path worked
        // only because a click gives the device time to open). Remember the
        // release and let the start path finish — it keeps a minimum capture
        // window and stops by itself. A real cancel still aborts the start.
        if (!discard) { pendingStop = true; return; }
        startingRecording = false;
        recordingGeneration += 1;
        pendingStop = false;
        return;
      }
      if (!recording) return;
      const session = recorderSession;
      // A tap shorter than the microphone start-up is not speech; sending it would
      // only earn a 400 from the transcriber. A cancelled take is also discarded.
      if (session) {
        session.discard = discard || Date.now() - session.startedAt < 500;
        session.cancelled = discard;
      }
      recording = false;
      microphoneWanted = false;
      listening = false;
      clearTimeout(recordTimer);
      clearTimeout(session?.minStopTimer);
      try { session?.recorder?.stop(); } catch (_) { /* already closed */ }
      stopMeter();
      detail = discard ? 'Recording cancelled' : 'Transcribing…';
      updateStatus();
    }

    async function finishServerRecording(session) {
      if (!session || session.recorder !== recorderSession?.recorder) return;
      const type = session.recorder?.mimeType || 'audio/webm';
      const blob = new Blob(session.chunks, { type });
      session.chunks = [];
      recorderSession = null;
      try { session.stream?.getTracks?.().forEach(track => track.stop()); } catch (_) { /* gone */ }
      detachBoost(session);
      if (session.discard || !blob.size) {
        const held = ((Date.now() - session.startedAt) / 1000).toFixed(1);
        detail = session.cancelled ? 'Recording cancelled'
          : blob.size ? `Take of ${held} s was empty — the microphone fed no audio; check the input device`
            : `Too short (${held} s) — hold Ctrl+Space, wait for "Recording", then speak`;
        updateStatus();
        return;
      }
      if (session.token !== transcribeToken) return;
      const language = String($('voice-language')?.value || preferredLanguage()).split('-')[0];
      const dictateParam = dictateNext ? '&dictate=1' : '';
      const wasDictate = dictateNext;
      dictateNext = false;
      const controller = typeof AbortController === 'function' ? new AbortController() : null;
      transcribeAbort = controller;
      try {
        const response = await fetch(`/voice/transcribe?language=${encodeURIComponent(language)}${dictateParam}`, {
          method: 'POST',
          headers: { 'Content-Type': type },
          body: blob,
          signal: controller ? controller.signal : undefined,
        });
        const payload = await response.json().catch(() => ({}));
        if (session.token !== transcribeToken) return;
        if (!response.ok || !payload.ok) {
          const code = payload?.error?.code || '';
          const message = payload?.error?.message || '';
          if (response.status === 400 && code === 'INVALID_REQUEST') {
            const held = ((Date.now() - session.startedAt) / 1000).toFixed(1);
            detail = `Too short (${held} s, ${Math.max(1, Math.round(blob.size / 1024))} kB) — hold Ctrl+Space while you speak`;
            updateStatus();
            return;
          }
          // Silence and decoder failures carry a message written for the user;
          // show it instead of hiding the reason behind a generic failure.
          if (code === 'STT_FAILED' && message) {
            detail = message;
            updateStatus();
            return;
          }
          throw new Error(message || 'Transcription failed');
        }
        const text = String(payload.text || '').trim();
        if (!text) {
          const level = typeof payload.level_dbfs === 'number'
            ? ` (peak ${Math.round(payload.level_dbfs)} dBFS)` : '';
          const tooQuiet = typeof payload.level_dbfs === 'number' && payload.level_dbfs < -20;
          detail = tooQuiet
            ? `Mic too quiet${level} — speak louder or move closer to the microphone`
            : `Heard nothing${level} — try again`;
          updateStatus();
          return;
        }
        if (isEcho(text)) {
          detail = "Ignored the assistant's own voice";
          updateStatus();
          return;
        }
        $('voice-transcript').textContent = text;
        if (wasDictate || payload.dictated) {
          detail = `Dictated (${payload.seconds}s)`;
          updateStatus();
          return;
        }
        const cloud = /groq/i.test(String(payload.engine || ''));
        detail = `${cloud ? 'Transcribed in the cloud' : 'Transcribed offline'} in ${payload.seconds}s`
          + (typeof payload.level_dbfs === 'number'
             ? ` · mic peak ${Math.round(payload.level_dbfs)} dB`
             : '');
        updateStatus();
        dispatch(text);
      } catch (error) {
        if (error?.name === 'AbortError' || session.token !== transcribeToken) return;
        detail = 'Local transcription failed — type instead';
        updateStatus();
      } finally {
        if (transcribeAbort === controller) transcribeAbort = null;
      }
    }

    function probeServerStt() {
      if (typeof fetch !== 'function') return;
      fetch('/voice/status', { headers: { Accept: 'application/json' } })
        .then(response => response.ok ? response.json() : null)
        .then(payload => {
          const electron = /Electron/i.test(navigator.userAgent || '');
          if (!payload?.available) {
            if (electron) {
              const button = $('mic-button');
              if (button) {
                button.disabled = true;
                button.title = 'Install the local transcriber: scripts/install-stt.sh';
              }
              detail = 'Local transcription is not installed — run scripts/install-stt.sh';
              updateStatus();
            }
            return;
          }
          // Chrome keeps Google's recogniser by default; a power user can opt
          // into the local engine with localStorage.setItem('galaxy.stt', 'local').
          let preferLocal = false;
          try { preferLocal = window.localStorage?.getItem('galaxy.stt') === 'local'; } catch (_) {}
          if (electron || preferLocal) serverStt = true;
        })
        .catch(() => { /* the browser path still works */ });
    }

    function startListening() {
      if (wakeEnabled && wake?.active) { wake.stop(); scheduleWake(8000); }
      if (!recognition) {
        detail = 'Microphone unavailable in this browser; typing still works';
        updateStatus();
        return false;
      }
      detail = '';
      microphoneWanted = true;
      recognition.lang = $('voice-language').value || 'en-GB';
      startMeter();
      startRecognition();
      updateStatus();
      return true;
    }

    function stopListening() {
      if (recording || startingRecording) {
        pttHeld = false;
        pttReleased = false;
        pendingStop = false;
        clearTimeout(pttFlushTimer);
        clearTimeout(restartTimer);
        try { if (recognition) recognition.abort(); } catch (_) { /* already closed */ }
        stopServerRecording();
        return;
      }
      microphoneWanted = false;
      pttHeld = false;
      pttReleased = false;
      pendingStop = false;
      clearTimeout(pttFlushTimer);
      clearTimeout(restartTimer);
      clearFinish();
      fragments = [];
      interimText = '';
      starting = false;
      listening = false;
      if (recognition) recognition.abort();
      stopMeter();
      updateStatus();
    }

    function isTypingTarget(target) {
      const tag = String(target?.tagName || '').toLowerCase();
      return tag === 'input' || tag === 'textarea' || tag === 'select' || target?.isContentEditable === true;
    }

    function pushToTalkStart(event) {
      if (event.ctrlKey && event.altKey && event.code === 'KeyD' && !event.repeat && !isTypingTarget(event.target)) {
        if (typeof event.preventDefault === 'function') event.preventDefault();
        dictateNext = true;
        if (speaking) stopSpeaking();
        if (serverStt) startServerRecording();
        else if (!microphoneWanted) startListening();
        return;
      }
      if (!event.ctrlKey || event.code !== 'Space' || event.repeat || isTypingTarget(event.target)) return;
      if (microphoneWanted) return;
      if (typeof event.preventDefault === 'function') event.preventDefault();
      pttReleased = false;
      pendingStop = false;
      pttHeld = serverStt ? startServerRecording() : startListening();
    }

    function pushToTalkEnd(event) {
      if (!pttHeld || (event.code !== 'Space' && event.key !== ' ')) return;
      if (typeof event.preventDefault === 'function') event.preventDefault();
      pttHeld = false;
      if (serverStt) {
        if (!recording) pendingStop = true;
        stopServerRecording();
        return;
      }
      if (!microphoneWanted) return;
      // Stop the microphone, but let the recognizer deliver its final phrase;
      // abort() here would discard the words the user just held the key to say.
      pttReleased = true;
      microphoneWanted = false;
      clearTimeout(restartTimer);
      try {
        if (recognition) recognition.stop(); else stopListening();
      } catch (_) {
        stopListening();
      }
      stopMeter();
      updateStatus();
      // Releasing the key means "send it now": a final result flushes immediately,
      // and this timer is the backstop when the recognizer stays silent.
      clearTimeout(pttFlushTimer);
      pttFlushTimer = setTimeout(() => flushNow(), 400);
    }

    if (recognition) {
      recognition.continuous = true;
      recognition.interimResults = true;
      recognition.maxAlternatives = 1;
      recognition.onstart = () => {
        starting = false;
        listening = true;
        finalizedResults.clear();
        updateStatus();
      };
      recognition.onspeechstart = () => { clearFinish(); };
      recognition.onspeechend = () => { if (finishTimer === null) scheduleFinish(); };
      recognition.onresult = event => {
        let changed = false;
        const interim = [];
        for (let index = event.resultIndex; index < event.results.length; index++) {
          if (finalizedResults.has(index)) continue;
          const result = event.results[index];
          const rawText = result[0].transcript.trim();
          if (!rawText) continue;
          if (isEcho(rawText)) {
            if (result.isFinal) finalizedResults.add(index); // Discard our own tail once, not on every final.
            continue;
          }
          let text = rawText;
          if (WAKE_RE.test(text)) {
            if (speaking) { stopSpeaking(); interrupt(); }
            text = text.replace(WAKE_RE, '').trim();
            if (!text) {
              if (result.isFinal) finalizedResults.add(index);
              detail = 'Listening — go ahead, sir';
              updateStatus();
              continue;
            }
          }
          if (voiceRoutes.some(route => route.immediate && matchRoute(route, text))) {
            finalizedResults.add(index); // Do not repeat an interim command on its final.
            dispatch(text);
            return;
          }
          changed = true;
          if (result.isFinal) {
            finalizedResults.add(index);
            fragments.push(text);
          } else interim.push(text);
        }
        if (!changed) return;
        clearFinish();
        interimText = interim.join(' ');
        if (speaking) stopSpeaking();
        showTranscript();
        if (pttReleased && !interimText) flushNow();
        else scheduleFinish();
      };
      recognition.onend = () => {
        starting = false;
        listening = false;
        if (pttReleased) { flushNow(); return; }
        // Chrome may end a continuous session on silence; never flush early.
        if (finishTimer === null) scheduleFinish();
        updateStatus();
        if (microphoneWanted && !document.hidden) restartTimer = setTimeout(startRecognition, 150);
      };
      recognition.onerror = event => {
        if (event.error === 'aborted') return;
        if (event.error === 'no-speech') { detail = 'No speech heard; try again'; updateStatus(); return; }
        microphoneWanted = false;
        listening = false;
        starting = false;
        clearFinish();
        fragments = [];
        interimText = '';
        const offline = event.error === 'network' || event.error === 'service-not-allowed';
        detail = event.error === 'not-allowed'
          ? 'Microphone permission denied — allow it in browser settings'
          : event.error === 'audio-capture' ? 'No microphone found'
            : offline ? 'Switching to the offline transcriber…'
              : 'Browser recognition unavailable — check your connection or type';
        updateStatus();
        if (offline) {
          serverStt = true;
          startServerRecording();
        }
      };
    } else {
      $('mic-button').disabled = true;
      detail = 'Microphone unavailable in this browser; typing still works';
    }
    $('mic-button').addEventListener('click', () => {
      if (serverStt) {
        if (recording || startingRecording) stopServerRecording(); else startServerRecording();
        return;
      }
      if (microphoneWanted) stopListening(); else startListening();
    });
    $('voice-language').addEventListener('change', event => {
      rememberLanguage(event.target?.value || '');
      if (serverStt) {
        // The next recording picks up the new language; cancel the current take
        // instead of transcribing it with the old one.
        if (recording || startingRecording) stopServerRecording(true);
        return;
      }
      const resume = microphoneWanted;
      stopListening();
      if (resume) startListening();
    });
    $('voice-output').addEventListener('change', event => {
      rememberVoice(event.target?.value || '');
      updateStatus();
    });
    // Warm the capture device on the first gesture. A cold getUserMedia costs
    // about a second here, which is longer than a quick push-to-talk press, so
    // the first Ctrl+Space used to release before the device opened. Priming
    // once makes the key path behave like the icon path; the track is stopped
    // immediately and nothing is recorded.
    let primed = false;
    function primeMicrophone() {
      if (primed || recording || startingRecording) return;
      if (!navigator.mediaDevices?.getUserMedia) return;
      primed = true;
      navigator.mediaDevices.getUserMedia(RECORD_AUDIO)
        .then(stream => {
          try { stream.getTracks().forEach(track => track.stop()); } catch (_) { /* gone */ }
        })
        .catch(() => { primed = false; });
    }
    document.addEventListener('pointerdown', primeMicrophone, { once: true, passive: true });
    document.addEventListener('keydown', pushToTalkStart);
    document.addEventListener('keyup', pushToTalkEnd);
    // The Electron shell owns a system-wide shortcut. A desktop shortcut is a
    // real user gesture, so it may unlock speech before the first page click.
    window.jarvisDesktop?.onPushToTalk?.(() => {
      unlocked = true;
      if (speaking) stopSpeaking();
      if (recording || startingRecording) {
        stopServerRecording();
      } else if (serverStt) {
        startServerRecording();
      } else if (microphoneWanted) {
        stopListening();
      } else {
        startListening();
      }
    });
    window.jarvisDesktop?.onDictate?.(() => {
      unlocked = true;
      if (speaking) stopSpeaking();
      if (recording || startingRecording) {
        stopServerRecording();
      } else if (serverStt) {
        dictateNext = true;
        startServerRecording();
      } else if (microphoneWanted) {
        stopListening();
      } else {
        dictateNext = true;
        startListening();
      }
    });
    // Seed the recognition language before the first microphone use; a stored
    // explicit choice wins over the OS locale guess.
    const languageSelect = $('voice-language');
    if (languageSelect) languageSelect.value = preferredLanguage();
    probeServerStt();
    populateVoices();
    if (synthesis && typeof synthesis.addEventListener === 'function') {
      synthesis.addEventListener('voiceschanged', populateVoices);
    }
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) { stopListening(); stopSpeaking(); }
    });

    const controller = {
      speak, stopSpeaking, startListening, stopListening, wakeRecord, dispatch, inspect: inspectSentence,
      speakStream: streamSpeech, finishStream: finishSpeech,
      parseAddress: speechAddress, routes: voiceRoutes, isEcho, voices: populateVoices,
      chooseVoice,
      setThinking(value) { thinking = Boolean(value); updateStatus(); },
      get speaking() { return speaking; },
      get thinking() { return thinking; },
      get listening() { return listening; },
      // The Operator panel starts jobs outside the chat request; it needs the
      // same voice-derived language so narration is not read in Polish by an
      // English voice.
      get replyLanguage() { return replyLanguage(); }
    };
    updateStatus();
    return controller;
  };
})();
