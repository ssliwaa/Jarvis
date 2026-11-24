"""Deterministic request router for the chat box.

The old regex only knew whether a message began with an operator verb.  This
module makes the decision explicit, gives the UI a plan, and keeps genuinely
ambiguous imperatives out of the Operator until the user supplies an object.
No model call and no hidden side effect.
"""
from __future__ import annotations

import re

try:
    import web_research
    WEB_RE = web_research.RESEARCH_HINTS
except Exception:
    web_research = None
    WEB_RE = re.compile(r"\b(?:search\s+the\s+web|google|wyszukaj\s+w\s+sieci)\b", re.I)

OPERATOR_RE = re.compile(
    r"^\s*(?:(?:hello|hi|cześć|czesc|siema|siemanko|witaj|witajcie|witam|"
    r"dzień\s+dobry|dzien\s+dobry|dobry\s+wieczór|dobry\s+wieczor|good\s+morning|"
    r"good\s+afternoon|good\s+evening|ok|okay|dobra|dobrze|jasne|hej|hey|jarvis|"
    r"no\s+to|więc|wiec|so|now|then|yo|cóż|coz|well)\s*[,:;-]?\s*)*"
    r"(?:(?:proszę|prosze|please|kindly)\s+|"
    r"(?:czy\s+możesz|czy\s+mozesz|czy\s+mógłbyś|czy\s+moglbys|czy\s+mogłabyś|czy\s+moglabys|"
    r"możesz|mozesz|mógłbyś|moglbys|mogłabyś|moglabys|can\s+you|could\s+you|would\s+you|will\s+you)\s+(?:please\s+|proszę\s+|prosze\s+)?(?:mi\s+|me\s+)?|"
    r"(?:chciałbym\s+(?:żebyś\s+|zebys\s+)?|chcialbym\s+(?:żebyś\s+|zebys\s+)?|chciałabym\s+(?:żebyś\s+|zebys\s+)?|chcialabym\s+(?:żebyś\s+|zebys\s+)?|"
    r"i\s+want\s+(?:you\s+to\s+)?|i\s+would\s+like\s+(?:you\s+to\s+)?|i\'d\s+like\s+(?:you\s+to\s+)?|"
    r"weź\s+|wez\s+|pomóż\s+mi\s+|pomoz\s+mi\s+|help\s+me\s+(?:to\s+)?)?)?"
    r"(?:otwórz|otworz|otworzyć|otworzyc|uruchom|uruchomić|uruchomic|odpal|odpalić|odpalic|wykonaj|wykonać|wykonac|zrób|zrob|zrobić|zrobic|"
    r"przetestuj|przetestować|przetestowac|testuj|testować|testowac|ztestuj|ztestować|ztestowac|"
    r"sprawdź|sprawdz|sprawdzić|sprawdzic|zbadaj|zbadać|zbadac|badaj|badać|badac|przebadaj|przebadać|przebadac|przebadajmy|"
    r"zweryfikuj|zweryfikować|zweryfikowac|weryfikuj|weryfikować|weryfikowac|"
    r"zwaliduj|zwalidować|zwalidowac|waliduj|walidować|walidowac|odpytaj|odpytać|odpytac|odpytuj|odpytywać|odpytywac|"
    r"przetestujmy|sprawdźmy|sprawdzmy|zbadajmy|zweryfikujmy|"
    r"zrestartuj|zrestartować|zrestartowac|restartuj|restartować|restartowac|zresetuj|zresetować|zresetowac|resetuj|resetować|resetowac|"
    r"przeładuj|przeładować|przeladuj|przeladowac|reload|"
    r"napisz|napisać|napisac|zapisz|zapisać|zapisac|edytuj|edytować|edytowac|zmień|zmien|zmienić|zmienic|"
    r"utwórz|utworz|utworzyć|utworzyc|stwórz|stworz|stworzyć|stworzyc|pobierz|pobrać|pobrac|wgraj|wgrać|wgrac|"
    r"zainstaluj|zainstalować|zainstalowac|odinstaluj|odinstalować|odinstalowac|"
    r"odwiedź|odwiedz|odwiedzić|odwiedzic|wejdź|wejdz|wejść|wejsc|kliknij|kliknąć|kliknac|"
    r"wypełnij|wypelnij|wypełnić|wypelnic|wpisz|wpisać|wpisac|znajdź|znajdz|znaleźć|znalezc|"
    r"przenieś|przenies|przenieść|przeniesc|usuń|usun|usunąć|usunac|skasuj|skasować|skasowac|"
    r"wymaż|wymaz|wymazać|wymazac|wyczyść|wyczysc|wyczyścić|wyczyscic|skopiuj|skopiować|skopiowac|"
    r"wygeneruj|wygenerować|wygenerowac|przetwórz|przetworz|przetworzyć|przetworzyc|przeczytaj|przeczytać|przeczytac|"
    r"zeskanuj|zeskanować|zeskanowac|przeskanuj|przeskanować|przeskanowac|skanuj|skanować|skanowac|zrzut|"
    r"przeanalizuj|przeanalizować|przeanalizowac|analizuj|analizować|analizowac|"
    r"zoptymalizuj|zoptymalizować|zoptymalizowac|optymalizuj|optymalizować|optymalizowac|"
    r"popraw|poprawić|poprawic|ulepsz|ulepszyć|ulepszyc|napraw|naprawić|naprawic|przejrzyj|przejrzeć|przejrzec|"
    r"zrefaktoryzuj|zrefaktoryzować|zrefaktoryzowac|zrefaktoruj|zrefaktorować|zrefaktorowac|audytuj|audytować|audytowac|"
    r"zdiagnozuj|zdiagnozować|zdiagnozowac|diagnozuj|diagnozować|diagnozowac|"
    r"skompiluj|skompilować|skompilowac|zbuduj|zbudować|zbudowac|wyślij|wyslij|wysłać|wyslac|opublikuj|opublikować|opublikowac|"
    r"przetłumacz|przetlumacz|przetłumaczyć|przetlumaczyc|streść|stresc|streścić|strescic|"
    r"zamknij|zamknąć|zamknac|pokaż|pokaz|pokazać|pokazac|policz|policzyć|policzyc|zmierz|zmierzyć|zmierzyc|wyświetl|wyswietl|wyświetlić|wyswietlic|"
    # Playback and audio are real Operator actions (media_control, app_control),
    # not chat prose: "play music on Spotify" must reach the Operator.
    r"zagraj|zagrać|zagrac|odtwórz|odtworz|odtworzyć|odtworzyc|puść|pusc|puścić|puscic|włącz|wlacz|włączyć|wlaczyc|"
    r"wycisz|wyciszyć|wyciszyc|odcisz|odciszyć|odciszyc|pogłoś|pogłos|pogłośnić|poglosnic|ścisz|scisz|ściszyć|sciszyc|pauzuj|pauzować|pauzowac|"
    r"test|retest|benchmark|probe|ping|check|verify|validate|diagnose|debug|"
    r"restart|reboot|reload|reset|kill|start|stop|"
    r"open|run|execute|create|build|develop|code|implement|write|edit|delete|"
    r"remove|download|upload|install|uninstall|launch|close|click|fill|search|find|"
    r"visit|go\s+to|take\s+(?:a\s+)?screenshot|summari[sz]e|translate|generate|"
    r"play|pause|resume|mute|unmute|skip|next\s+(?:track|song)|previous\s+(?:track|song)|"
    r"convert|scan|analyze|analyse|audit|inspect|examine|review|refactor|optimize|optimise|"
    r"improve|upgrade|fix|repair|debug|solve|patch|dispatch|trigger|move|copy|send|publish)\b", re.I)

# An explicit "use the operator" can precede the action ("Użyj operatora i
# otwórz Opera GX."). The action verb no longer has to be the first word.
OPERATOR_CALL = re.compile(
    r"^\s*(?:(?:hello|hi|cześć|czesc|siema|siemanko|witaj|witajcie|witam|"
    r"dzień\s+dobry|dzien\s+dobry|dobry\s+wieczór|dobry\s+wieczor|good\s+morning|"
    r"good\s+afternoon|good\s+evening|ok|okay|dobra|dobrze|jasne|hej|hey|jarvis|"
    r"no\s+to|więc|wiec|so|now|then|yo|cóż|coz|well)\s*[,:;-]?\s*)*"
    r"(?:(?:proszę|prosze|please|kindly)\s+)?"
    r"(?:(?:czy\s+możesz|czy\s+mozesz|czy\s+mógłbyś|czy\s+moglbys|can\s+you|could\s+you|would\s+you|will\s+you)\s+(?:please\s+|proszę\s+|prosze\s+)?(?:mi\s+|me\s+)?)?"
    r"(?:(?:użyj|uzyj|użyć|uzyc|skorzystaj\s+z|skorzystać\s+z|skorzystac\s+z|odpal|odpalić|odpalic|uruchom|uruchomić|uruchomic|włącz|wlacz|włączyć|wlaczyc|wyślij|wyslij|wysłać|wyslac|przekaż|przekaz|przekazać|przekazac|zleć|zlec|zlecić|zlecic|poproś|popros|poprosić|poprosic)\s+(?:to\s+)?(?:do\s+)?(?:the\s+|swojego\s+|twojego\s+)?operator(?:a|owi)?(?![\w-])"
    r"|(?:niech\s+operator(?![\w-]))"
    r"|(?:(?:use|dispatch|run|launch|start|call|ask|tell|have|let)\s+(?:the\s+)?operator(?![\w-])))"
    r"\b(?:\s*(?:[,:;]|i|and|żeby|zeby|aby|to|do|for)\s*)?(.*)$", re.I | re.S)

# Creative/writing and translation requests are answered by the chat brain
# unless they name a real computer object (file, app, URL, test suite).
CREATIVE_TASK = re.compile(
    r"^\s*(?:napisz|napisz\s+mi|streść|stresc|streść\s+mi|przetłumacz|przetlumacz|"
    r"opowiedz|wyjaśnij|wyjasnij|wymyśl|wymysl|ułóż|uloz|zaplanuj|zaplanuj\s+mi|"
    r"przeanalizuj|przeanalizuj\s+mi|oceń|ocen|porównaj|porownaj)\b",
    re.I)
NOTES_REFERENCE = re.compile(
    r"\b(?:notatk\w*|notatek|notatce|notatkach|notatka|notatki|notes?|z\s+notatek|"
    r"w\s+notatkach|moich\s+notatek)\b", re.I)
COMPUTER_OBJECT = re.compile(
    r"\b(?:plik\w*|file\w*|files\b|folder\w*|folders\b|dir\w*|dirs\b|directory\w*|directories\b|katalog\w*|"
    r"aplikacj\w*|application\w*|app\w*|apps\b|program\w*|programs\b|software\b|system\w*|os\b|linux\b|ubuntu\b|"
    r"okn\w*|window\w*|windows\b|przycisk\w*|button\w*|"
    r"stron\w*|website\w*|webpage\w*|web-site\w*|site\w*|landing\s*page\w*|portfolio\w*|homepage\w*|"
    r"link\w*|adres\w*|url|terminal\w*|przeglądark\w*|przegladark\w*|browser\w*|"
    r"oper[ay]|chrome|firefox|edge|profil\w*|profile\w*|proces\w*|process\w*|processes\b|skrypt\w*|script\w*|scripts\b|"
    r"repozytori\w*|repository\w*|projekt\w*|project\w*|test\w*|tests\b|log\w*|logs\b|"
    r"kod\w*|code\b|codebase\b|źródł\w*|zrodl\w*|source\w*|sources\b|repo\b|"
    r"backend\w*|frontend\w*|moduł\w*|modul\w*|module\w*|modules\b|architektur\w*|architecture\b|"
    r"funkcj\w*|function\w*|functions\b|klas\w*|class\w*|classes\b|metod\w*|method\w*|methods\b|"
    r"komponent\w*|component\w*|pakiet\w*|package\w*|git\w*|baza\w*|bazy\w*|database\w*|db\b|"
    r"kino\b|player\w*|odtwarzacz\w*|bot\w*|crawler\w*|scraper\w*|"
    r"agent\w*|agents\b|agenci\b|agentów\b|agentow\b|agentom\b|agentami\b|"
    r"opencode\b|hermes\b|claude\b|antigravity\b|"
    r"serwis\w*|service\w*|services\b|usług\w*|uslugi\w*|serwer\w*|server\w*|servers\b|demon\w*|daemon\w*|systemd\b|"
    r"mcp\b|mcp-server\w*|narzędzi\w*|narzedzi\w*|tool\w*|tools\b|"
    r"endpoint\w*|endpoints\b|port\w*|ports\b|porty\b|portów\b|portow\b|api\b|apis\b|sieć\b|sieci\b|network\b|"
    r"środowisk\w*|srodowisk\w*|environment\w*|env\b|sandbox\w*|piaskownic\w*|bwrap\b)\b", re.I)

CODE_OBJECT = re.compile(
    r"\b(?:kod\w*|code\b|codebase\b|źródł\w*|zrodl\w*|source\w*|repo\b|repozytori\w*|"
    r"architektur\w*|skrypt\w*|backend\w*|frontend\w*)\b", re.I)

CODE_ACTION = re.compile(
    r"\b(?:przeskanuj\w*|zeskanuj\w*|skanuj\w*|skan\w*|przeanalizuj\w*|analizuj\w*|zbadaj\w*|przebadaj\w*|przebad\w*|"
    r"sprawdź\w*|sprawdz\w*|przejrzyj\w*|przegląd\w*|przeglad\w*|audyt\w*|"
    r"ulepsz\w*|popraw\w*|zoptymalizuj\w*|optymalizuj\w*|napraw\w*|zrefaktoryzuj\w*|refaktor\w*|"
    r"scan\w*|analy[sz]\w*|audit\w*|inspect\w*|examine\w*|review\w*|check\w*|"
    r"improve\w*|upgrade\w*|refactor\w*|optimize\w*|optimise\w*|fix\w*|debug\w*)\b", re.I)

DEV_OBJECT = re.compile(
    r"\b(?:stron\w*|witryn\w*|portal\w*|website\w*|webpage\w*|web-site\w*|site\w*|landing\s*page\w*|portfolio\w*|homepage\w*|"
    r"aplikacj\w*|application\w*|app\w*|apps\b|program\w*|software\b|system\w*|os\b|linux\b|ubuntu\b|"
    r"skrypt\w*|script\w*|scripts\b|bot\w*|bots\b|crawler\w*|scraper\w*|"
    r"serwer\w*|server\w*|backend\w*|frontend\w*|api\w*|endpoint\w*|microservice\w*|mikroserwis\w*|"
    r"moduł\w*|modul\w*|module\w*|kod\w*|code\w*|codebase\w*|funkcj\w*|function\w*|komponent\w*|component\w*|"
    r"narzędzi\w*|narzedzi\w*|tool\w*|tools\b|plugin\w*|wtyczk\w*|rozszerzeni\w*|extension\w*|"
    r"baza\w*|bazy\w*|database\w*|db\b|kino\b|player\w*|odtwarzacz\w*)\b", re.I)

DEV_ACTION = re.compile(
    r"\b(?:build\w*|create\w*|make\w*|develop\w*|code\w*|implement\w*|generate\w*|construct\w*|"
    r"fix\w*|repair\w*|patch\w*|debug\w*|resolve\w*|solve\w*|remedy\w*|correct\w*|"
    r"zbuduj\w*|stwórz\w*|stworz\w*|utwórz\w*|utworz\w*|wygeneruj\w*|napisz\w*|zaimplementuj\w*|przygotuj\w*|"
    r"napraw\w*|popraw\w*|rozwiaż\w*|rozwiaz\w*|załataj\w*|zalataj\w*|odpluskw\w*|usuń\s+bł[ęe]d\w*|usun\s+blad\w*|"
    r"wdróż\w*|wdroz\w*|postaw\w*|uruchom\w*|odpal\w*|odpalaj\w*|uruchamiaj\w*)\b", re.I)

AGENT_OBJECT = re.compile(
    r"\b(?:agent\w*|agents|agenci|agentów|agentow|agentom|agentami|"
    r"opencode|hermes|claude(?:\s+code)?|antigravity|subagent\w*|subagents)\b", re.I)

AGENT_ACTION = re.compile(
    r"\b(?:test\w*|przetest\w*|ztest\w*|sprawdź\w*|sprawdz\w*|check\w*|"
    r"zbad\w*|bad\w*|zweryfik\w*|weryfik\w*|zwalid\w*|walid\w*|odpyt\w*|ping\w*|probe\w*|"
    r"działa\w*|dziala\w*|działają\w*|dzialaja\w*|odpowiada\w*|odpowiadają\w*|odpowiadaja\w*|"
    r"responsive\w*|responsiveness|working|alive|available|dostępn\w*|dostepn\w*|"
    r"uruchom\w*|odpal\w*|włącz\w*|wlacz\w*|run\w*|launch\w*|start\w*|execute\w*|"
    r"status\w*|stan\w*|health\w*)\b", re.I)

SERVICE_OBJECT = re.compile(
    r"\b(?:serwis\w*|service\w*|services\b|usług\w*|uslugi\w*|serwer\w*|server\w*|"
    r"demon\w*|daemon\w*|systemd\b|proces\w*|procesy|procesów|procesow|process\w*|processes\b)\b", re.I)

SERVICE_ACTION = re.compile(
    r"\b(?:restart\w*|zrestartuj\w*|reboot\w*|reload\w*|przeładuj\w*|przeladuj\w*|"
    r"start\w*|uruchom\w*|odpal\w*|włącz\w*|wlacz\w*|stop\w*|zatrzymaj\w*|wyłącz\w*|wylacz\w*|"
    r"kill\w*|zabij\w*|ubij\w*|status\w*|stan\w*|sprawdź\w*|sprawdz\w*|check\w*|"
    r"działa\w*|dziala\w*|działają\w*|dzialaja\w*|running|active|aktywn\w*|alive)\b", re.I)
# Lookup verbs describe a web/notes question unless they name a computer object.
LOOKUP_TASK = re.compile(r"^\s*(?:znajdź|znajdz|find|search|sprawdź|sprawdz|check)\b", re.I)
WEB_LOOKUP = re.compile(
    r"\b(?:restauracj\w*|hotel\w*|cen\w*|pogod\w*|news\w*|najnowsz\w*|aktualn\w*|"
    r"w\s+internecie|w\s+sieci|w\s+mieście|w\s+miescie|w\s+okolicy)\b", re.I)

# Local machine state is real Operator work, not a chat answer: the Operator
# owns system_monitor, disk/memory/process reads and the file counts. Without
# these nouns "sprawdź ile wolnego miejsca na dysku" fell into the web lane and
# the answer was "this lane cannot read your disk".
SYSTEM_STATE = re.compile(
    r"\b(?:dysk\w*|partycj\w*|miejsc\w*|pami[ęe]c\w*|ram\b|ramu\b|cpu\b|procesor\w*|"
    r"temperatur\w*|zasob\w*|obci[ąa]żeni\w*|uptime|proces\w*|procesy|procesów|procesow|"
    r"wolnego\s+miejsca|wolnej\s+pami[ęe]ci)\b", re.I)
# A question about *this* machine needs a first-person or measurement marker, so
# "jak działa pamięć RAM" stays general knowledge while "ile RAM mam teraz" acts.
MACHINE_MARKER = re.compile(
    r"\b(?:mam|mamy|mój|moj|moja|moje|moich|u\s+mnie|w\s+systemie|na\s+dysku|teraz|"
    r"zosta[łl]o|zostalo|wolne\w*|wolnej|wolnego|zaj[ęe]te\w*)\b", re.I)
# Destructive verbs may not start an Operator job from chat without an explicit
# confirmation: in Full mode the Operator deletes without asking, and a plain
# sentence such as "usuń wszystkie pliki z Sejf" used to be queued silently.
DESTRUCTIVE = re.compile(
    r"\b(?:usuń|usun|usunąć|usunac|skasuj|skasować|skasowac|wymaż|wymaz|wymazać|wymazac|"
    r"wyczyść|wyczysc|wyczyścić|wyczyscic|delete|remove|wipe|format|erase|drop\s+table)\b", re.I)
BENIGN_BUG_FIX = re.compile(
    r"\b(?:usuń|usun|usunąć|usunac|remove|delete)\s+(?:te\s+|wszystkie\s+|the\s+|these\s+|all\s+)?(?:bł[ęe]d\w*|usterk\w*|warning\w*|ostrzeżeni\w*|bugs?|errors?|warnings?)\b",
    re.I)
# Scrubbing the bug-fix idiom also removes its verb, so the idiom only excuses
# itself when nothing that could be a second delete target follows it in the
# same request: "usuń te błędy i plik old.py" deletes a real file too.
CONJUNCTIVE_TARGET = re.compile(
    r"(?:\b(?:i|oraz|and)\b|[,;])\s*"
    r"(?:\b(?:plik\w*|folder\w*|katalog\w*|dane|danych|log\w*|wszystkie|wszystko|sejf|all|everything)\b"
    r"|[^,;!?\s]+\.(?:py|json|md|txt|csv|log|js|png|jpg|jpeg|zip|pdf|yaml|yml)\b"
    r"|[/~][^\s,;.]+)",
    re.I)


def _is_destructive(text: str) -> bool:
    """Detect destructive intent while ignoring benign bug-fix idioms ('usuń błędy').

    The idiom is benign only when it stands alone: if scrubbing it would also
    hide a second conjunctive target ("usuń te błędy i plik old.py"), the
    sentence is still destructive.
    """
    text = str(text or "")
    scrubbed = BENIGN_BUG_FIX.sub("", text)
    if scrubbed != text and not DESTRUCTIVE.search(scrubbed):
        if CONJUNCTIVE_TARGET.search(scrubbed):
            return True
    return bool(DESTRUCTIVE.search(scrubbed))
CONFIRM_PREFIX = re.compile(
    r"^\s*(?:potwierdzam|tak,?\s*potwierdzam|confirm(?:ed)?|yes,?\s*confirm)\s*[:,]?\s*(.+)$",
    re.I | re.S)
# A destructive-looking sentence that names files, folders or paths is a real
# task, never a queue cancel ("usuń wszystko z kolejki" vs "usuń pliki z Sejf").
FILE_TARGET = re.compile(
    r"(?:/|~/|\b(?:plik\w*|folder\w*|katalog\w*|dysk\w*|katalogu)\b|"
    r"\.(?:txt|md|pdf|docx|xlsx|pptx|csv|json|png|jpg|zip|py)\b)", re.I)

# "Co potrafisz?" belongs to the live capability registry, not to the notes.
CAPABILITY_INTENT = re.compile(
    r"^\s*(?:co\s+(?:dokładnie\s+|tak\s+)?potrafisz|jakie\s+masz\s+"
    r"(?:możliwości|mozliwosci|narzędzia|narzedzia|funkcje|umiejętności|umiejetnosci)|"
    r"what\s+can\s+you\s+do|list\s+your\s+(?:capabilities|tools))", re.I)

# Verbs that are useful alone only in a real operator context; with no object
# they are a request to clarify, not permission to start a tool run.
VAGUE = re.compile(r"^\s*(?:zrób|zrob|sprawdź|sprawdz|znajdź|znajdz|otwórz|otworz|uruchom|"
                   r"wygeneruj|stwórz|stworz|napisz|zapisz|send|check|find|open|run|"
                   r"create|write|search|do|make)\b", re.I)

# Object phrases that still name nothing concrete: "zrób coś", "sprawdź to".
TARGETLESS = {"to", "co", "coś", "cos", "cokolwiek", "mi", "something", "anything",
              "it", "this", "that"}

# Local job control. These are whole-message patterns on purpose: they must never
# swallow an ordinary question ("co robisz z plikiem?") or an operator task, and
# they are answered from the live Operator state without a model call.
JOB_STATUS = re.compile(
    r"^\s*(?:co\s+(?:(?:teraz\s+)?robisz(?:\s+teraz)?|robi\s+operator|się\s+(?:teraz\s+)?dzieje)|"
    r"jaki\s+(?:jest\s+)?status(?:\s+(?:zadania|operatora))?|status\s+(?:zadania|operatora)|"
    r"what\s+are\s+you\s+doing(?:\s+(?:right\s+)?now|\s+at\s+the\s+moment)?|"
    r"what'?s\s+the\s+status)\s*[?.!]*\s*$", re.I)
JOB_QUEUE = re.compile(
    r"^\s*(?:co\s+jest\s+w\s+kolejce|co\s+czeka\s+w\s+kolejce|które\s+zadanie\s+czeka|"
    r"ile\s+zadań\s+czeka|kolejka(?:\s+zadań)?|queue|what'?s\s+queued|queued\s+jobs?)\s*[?.!]*\s*$", re.I)
# A cancel may name what it cancels and add an offhand reason. The real spoken
# request "cancel this youtube I don't want it" reached the general lane (and was
# answered with "this lane can't cancel anything") because only the exact wording
# "stop the job" matched. The grammar stays bounded — verb, one determiner, one
# known subject, an explicitly anchored reason — so a real task such as
# "zatrzymaj proces Opera GX" still belongs to the Operator.
CANCEL_VERB = (
    r"(?:cancel|stop|abort|halt|anuluj|odwołaj|odwolaj|przerwij|zatrzymaj|"
    r"zakończ|zakoncz|porzuć|porzuc|przestań|przestan|wyłącz|wylacz|"
    r"usuń|usun|skasuj|remove|delete)"
)
CANCEL_DETERMINER = (
    r"(?:this|that|it|the|my|ten|tego|to|tamto|tę|te|obecne|bieżące|biezace|current|running)"
)
CANCEL_SUBJECT = (
    r"(?P<subject>youtube|yt|muzyk\w*|music|spotify|playback|odtwarzani\w*|video|film\w*|"
    r"piosenk\w*|songs?|playlist\w*|task|job|zadanie|zadania|zadanko|operator\w*|"
    r"everything|all|wszystko|wszystkie|wszystkich|queue|kolejk\w*)"
)
CANCEL_REASON = (
    r"(?:i\s+don'?t\s+want\b.*|i\s+changed\s+my\s+mind\b.*|i\s+said\s+no\b.*|"
    r"nie\s+chc[eę]\b.*|bo\s+.*|zapomnij\b.*|forget\b.*|daj\s+spok[oó]j\b.*|"
    r"please|now|proszę|prosze)"
)
JOB_CANCEL = re.compile(
    r"^\s*(?:please\s+|proszę\s+|prosze\s+)?" + CANCEL_VERB +
    r"(?:\s+" + CANCEL_DETERMINER + r")?"
    r"(?:\s+" + CANCEL_SUBJECT +
    r"(?:\s+(?:tasks?|jobs?|zadania|zadań|prac\w*|robot\w*))?)?"
    r"(?:\s+z\s+(?:kolejki|kolejki|queue))?"
    r"(?:\s*(?:,\s*)?" + CANCEL_REASON + r")?"
    r"\s*[.!?]*\s*$", re.I | re.S)

# A plea is a cancel without the verb: "nie chcę tego" is what the user actually
# appended to the live request, and it means the same thing as "anuluj to".
JOB_CANCEL_PLEA = re.compile(
    r"^\s*(?:nie\s+chc[eę](?:\s+ju[żz])?(?:\s+tego)?(?:\s+wi[eę]cej)?|"
    r"zapomnij\s+o\s+tym|forget\s+about\s+it|"
    r"daj\s+spok[oó]j(?:\s+z\s+(?:t[ąa]\s+|tym\s+)?(?:muzyk[ąa]|muzykę|spotify|youtube|tym|nimi))?)"
    r"\s*[.!?]*\s*$", re.I)

# Subjects that mean "not just this one": the active job *and* the queue.
CANCEL_EVERYTHING = {"everything", "all", "wszystko", "wszystkie", "wszystkich",
                     "queue", "kolejka", "kolejki", "kolejke", "kolejkę"}

# Kept for callers that used the old name; the wider pattern above replaced it.
JOB_STOP = JOB_CANCEL


def _job_route(intent, control, text, reason, label, lang):
    return {"intent": intent, "action": "job_control", "control": control, "task": text,
            "confidence": 1.0, "needs_confirmation": False, "lang": lang,
            "reason": reason, "label": label}


# These job-control patterns exist in Polish and English only. Diacritics are a
# bad language test ("co robisz?" has none yet is Polish), so a Polish function
# word decides instead, and English is the fallback only for the known English
# wordings.
_POLISH_JOB_WORDS = re.compile(
    r"\b(?:co|jaki|jaką|jakie|które|ile|jest|robi|robisz|dzieje|się|kolejce|"
    r"kolejka|zadań|zadanie|zadania|zadaniu|czeka|zatrzymaj|przerwij|operatora|anuluj|odwołaj|"
    r"przestań|przestan|zakończ|zakoncz|porzuć|porzuc|wyłącz|wylacz|"
    r"chcę|chce|tego|wszystko|daj|spokój|spokoj|zapomnij)\b", re.I)


def _job_lang(text):
    return "pl" if _POLISH_JOB_WORDS.search(text) else "en"


def _jev_upgrade(text, decision):
    """A configured Jev may upgrade an unsure answer to a live lookup.

    It can only *raise* a general/question answer to the web lane; it can never
    approve permissions, start an Operator run on its own, or override a decision
    the rules already made. With no key, a timeout or a bad answer the rule
    decision stands untouched.
    """
    if decision.get('action') not in ('general', 'notes'):
        return decision
    if len(text) > 400:
        return decision
    try:
        import jev_decision
        if not jev_decision.available():
            return decision
        result = jev_decision.decide(
            text, {'needs_live': jev_decision.noul(
                'needs_live',
                'Does answering this request require fresh information from the internet?')},
            timeout=2.0)
    except Exception:  # any Jev problem means: keep the deterministic decision
        return decision
    if jev_decision.yes(result, 'needs_live'):
        upgraded = dict(decision)
        upgraded.update(intent='web', action='web', confidence=0.7,
                        reason='Jev: needs live sources', label='WEB RESEARCH')
        return upgraded
    return decision


def classify(message: str) -> dict:
    """Rule decision, optionally sharpened by Jev when a key is configured."""
    decision = _classify_rules(message)
    if decision.get('action') == 'operator' and not decision.get('background'):
        if BACKGROUND_INLINE.search(str(message or '')):
            decision = dict(decision, background=True)
    try:
        return _jev_upgrade(str(message or '').strip(), decision)
    except Exception:
        return decision


TASK_LIKE_RE = re.compile(
    r"https?://|/[\w.-]+|[\"'`]|\.(?:txt|pdf|docx|xlsx|pptx|csv|json|png|jpg|zip)\b",
    re.I)


def _domain_plan(text: str) -> str | None:
    if CODE_OBJECT.search(text) and CODE_ACTION.search(text):
        is_polish = bool(re.search(
            r"\b(?:kod\w*|swój|swojego|twojego|przeskanuj\w*|sprawdź\w*|ulepsz\w*|przeanalizuj\w*|popraw\w*|zbadaj\w*|przebadaj\w*)\b",
            text, re.I))
        return ("Przeskanuję kod w katalogu projektu, zbadam architekturę, linter i testy za pomocą narzędzi Operatora oraz przygotuję listę ulepszeń."
                if is_polish else
                "I will scan the project codebase, inspect architecture, lint and tests using Operator tools, and report concrete upgrade candidates.")
    if AGENT_OBJECT.search(text) and AGENT_ACTION.search(text):
        is_polish = bool(re.search(
            r"\b(?:agenci|agentów|agentow|agentami|agenta|agentach|przetestuj\w*|sprawdź\w*|sprawdz\w*|działa\w*|dziala\w*|odpowiada\w*)\b",
            text, re.I))
        return ("Przetestuję dostępność i responsywność skonfigurowanych agentów (Antigravity, Claude Code, Hermes, OpenCode) narzędziami Operatora."
                if is_polish else
                "I will test the availability and responsiveness of configured external agents (Antigravity, Claude, Hermes, OpenCode) with Operator tools.")
    if SERVICE_OBJECT.search(text) and SERVICE_ACTION.search(text):
        is_polish = bool(re.search(
            r"\b(?:serwis\w*|usług\w*|uslugi\w*|serwer\w*|działa\w*|dziala\w*|zrestartuj\w*|sprawdź\w*|sprawdz\w*)\b",
            text, re.I))
        return ("Sprawdzę stan i procesy usług systemowych za pomocą narzędzi diagnostycznych Operatora."
                if is_polish else
                "I will inspect system services and process states using Operator diagnostic tools.")
    if DEV_OBJECT.search(text) and DEV_ACTION.search(text):
        is_polish = bool(re.search(
            r"\b(?:stron\w*|aplikacj\w*|skrypt\w*|zbuduj\w*|stwórz\w*|stworz\w*|napisz\w*|napraw\w*|popraw\w*|komponent\w*)\b",
            text, re.I))
        return ("Zbuduję, wdrożę lub naprawię wskazany komponent za pomocą narzędzi deweloperskich Operatora."
                if is_polish else
                "I will build, develop or repair the specified component using Operator development tools.")
    return None



# Compound pipeline connectors: multi-step requests chained in a single sentence
# ("Sprawdź w notatkach budżet X, porównaj w sieci ceny i zapisz tabelę na Pulpicie").
_CHAIN_SPLIT_RE = re.compile(
    r"(?:\s*;\s*|"
    r"\s*,?\s+(?:a\s+potem|a\s+następnie|a\s+nastepnie|następnie|nastepnie|potem|później|pozniej|"
    r"po\s+czym|i\s+wtedy|and\s+then|then|afterwards|next|finally|i\s+na\s+koniec)\s+|"
    r"\s*,\s+(?:i\s+)?(?=(?:sprawdź|sprawdz|znajdź|znajdz|wyszukaj|porównaj|porownaj|zapisz|utwórz|utworz|"
    r"stwórz|stworz|wygeneruj|wyślij|wyslij|uruchom|otwórz|otworz|przetestuj|przeanalizuj|przeskanuj|zeskanuj|napraw|zbuduj|"
    r"przypomnij|dodaj|usuń|usun|skopiuj|przenieś|przenies|pobierz|zrestartuj|"
    r"check|find|search|compare|save|write|create|build|generate|send|run|open|test|analyze|scan|fix|remind|delete|copy|move|download|restart)\b)|"
    r"\s+i\s+(?=(?:zapisz|utwórz|utworz|stwórz|stworz|wygeneruj|wyślij|wyslij|uruchom|otwórz|otworz|"
    r"wyszukaj|porównaj|porownaj|przetestuj|napraw|zbuduj|przypomnij|pobierz|zrestartuj|skopiuj|przenieś|przenies)\b)|"
    r"\s+and\s+(?=(?:save|write|create|build|generate|send|run|open|search|compare|test|fix|remind|download|restart|copy|move)\b))",
    re.I,
)

_CLAUSE_VERB_RE = re.compile(
    r"\b(?:sprawdź|sprawdz|znajdź|znajdz|wyszukaj|poszukaj|porównaj|porownaj|zapisz|napisz|utwórz|utworz|"
    r"stwórz|stworz|wygeneruj|wyślij|wyslij|uruchom|odpal|otwórz|otworz|przetestuj|przeanalizuj|przeskanuj|zeskanuj|skanuj|zbadaj|"
    r"napraw|popraw|zbuduj|przypomnij|dodaj|usuń|usun|skasuj|wyczyść|wyczysc|skopiuj|przenieś|przenies|pobierz|zrestartuj|"
    r"check|find|search|lookup|compare|save|write|create|build|generate|send|run|open|test|analyze|scan|inspect|fix|repair|remind|add|delete|remove|copy|move|download|restart)\b",
    re.I,
)


def _clause_lane(clause: str) -> str:
    if NOTES_REFERENCE.search(clause):
        return "notes"
    if WEB_RE.search(clause) or WEB_LOOKUP.search(clause):
        return "web"
    if re.search(r"\b(?:przypomnij|remind|przypomnieni\w*|reminders?)\b", clause, re.I):
        return "reminder"
    if (TASK_LIKE_RE.search(clause) or COMPUTER_OBJECT.search(clause)
            or SYSTEM_STATE.search(clause) or DEV_OBJECT.search(clause)
            or re.search(r"\b(?:zapisz|utwórz|utworz|stwórz|stworz|wyślij|wyslij|pobierz|uruchom|otwórz|otworz|przeskanuj|zeskanuj|save|write|create|send|download|run|open|scan|pulpit\w*|desktop)\b", clause, re.I)):
        return "operator"
    return "general"


def parse_compound_steps(message: str) -> list[dict]:
    """Split a multi-step sentence into ordered actionable clauses with lane tags.

    Returns a non-empty list (2..6 items) ONLY when the message genuinely chains
    multiple actionable clauses; ordinary single-step sentences return ``[]``.
    """
    text = str(message or "").strip()
    if not text or len(text) < 24 or "\n" in text:
        return []
    cleaned = re.sub(
        r"^\s*(?:(?:hej|cześć|czesc|jarvis|ok|dobra|proszę|prosze|please)[,:;-]?\s+)*",
        "",
        text,
        flags=re.I,
    )
    raw_parts = [part.strip(" ,.;") for part in _CHAIN_SPLIT_RE.split(cleaned) if part and part.strip(" ,.;")]
    if len(raw_parts) < 2:
        return []
    steps = []
    for part in raw_parts[:6]:
        if len(part) < 6 or not _CLAUSE_VERB_RE.search(part):
            return []
        steps.append({
            "step": part[0].upper() + part[1:] if part else part,
            "lane": _clause_lane(part),
            "destructive": _is_destructive(part),
        })
    if len(steps) < 2:
        return []
    return steps



# Deictic workspace references ("na ekranie", "w aktywnym oknie", "ze schowka",
# "napraw ten błąd", "dodaj ten artykuł do Sejfu") bind to `workspace_context`.
WORKSPACE_DEICTIC_RE = re.compile(
    r"\b(?:na\s+ekranie|z\s+ekranu|co\s+mam\s+na\s+ekranie|on\s+(?:the\s+|my\s+)?screen|from\s+(?:the\s+|my\s+)?screen|"
    r"w\s+(?:aktywnym\s+|bieżącym\s+|biezacym\s+)oknie|in\s+the\s+(?:active\s+|current\s+)window|"
    r"ze\s+schowka|w\s+schowku|from\s+(?:the\s+)?clipboard|in\s+(?:the\s+)?clipboard)\b",
    re.I,
)


def _enrich_with_workspace(text: str) -> tuple[str, dict | None]:
    """Attach a bounded, non-intrusive workspace snapshot when available."""
    try:
        from operator_modules import workspace_context
        snap = workspace_context.capture_workspace_context(include_clipboard=False, recent_limit=5)
        if snap and snap.get("ok") and snap.get("summary"):
            return f"{text}\n[Active Workspace Context: {snap['summary']}]", snap
    except Exception:
        pass
    return text, None


BACKGROUND_PREFIX = re.compile(
    r'^\s*(?:/bg|/background|w\s+tle[:,]?|uruchom\s+w\s+tle[:,]?|zrób\s+w\s+tle[:,]?|zrob\s+w\s+tle[:,]?|run\s+in\s+(?:the\s+)?background[:,]?)\s+(.+)$',
    re.I | re.S,
)
BACKGROUND_INLINE = re.compile(
    r'\b(?:w\s+tle|in\s+the\s+background|asynchronously|asynchronicznie|nie\s+blokuj\w*)\b',
    re.I,
)


def _classify_rules(message: str) -> dict:
    text = str(message or "").strip()
    if not text:
        return {"intent": "empty", "confidence": 0.0, "action": "chat", "task": "", "needs_confirmation": False,
                "reason": "empty message", "label": "EMPTY"}
    for pattern, intent, control, reason, label in (
            (JOB_STATUS, "job_status", "status", "local job status", "OPERATOR · status"),
            (JOB_QUEUE, "job_queue", "queue", "local job queue", "OPERATOR · queue"),
            (JOB_CANCEL, "job_stop", "stop", "local job cancel", "OPERATOR · cancel"),
            (JOB_CANCEL_PLEA, "job_stop", "stop", "local job cancel", "OPERATOR · cancel")):
        match = pattern.match(text)
        if match:
            # A destructive sentence that names a file or path is a real task,
            # not "cancel the queue": "usuń wszystko z kolejki" vs
            # "usuń wszystko z katalogu Sejf".
            if intent == "job_stop" and FILE_TARGET.search(text):
                continue
            # Answer from the live Operator state; no model call, no new job.
            route = _job_route(intent, control, text, reason, label, _job_lang(text))
            subject = (match.groupdict().get("subject") or "").strip().casefold()
            if subject:
                route["subject"] = subject
                # "cancel everything" / "anuluj wszystko" clears the queue too.
                if subject in CANCEL_EVERYTHING:
                    route["control"] = "cancel_all"
            return route
    confirm = CONFIRM_PREFIX.match(text)
    if confirm:
        task = confirm.group(1).strip()
        destructive = _is_destructive(task)
        return {"intent": "operator", "confidence": 1.0, "action": "operator", "task": task,
                "needs_confirmation": False, "destructive": destructive, "confirmed": True,
                "reason": "explicit confirmation of a destructive task",
                "label": "OPERATOR · confirmed", "plan": _plan(task)}
    explicit = re.match(r"^(?:/operator|operator:)\s*(.*)$", text, re.I | re.S)
    if explicit:
        task = explicit.group(1).strip()
        if not task:
            return {"intent": "operator", "confidence": 0.6, "action": "clarify", "task": text,
                    "needs_confirmation": True, "reason": "explicit /operator without a task",
                    "label": "OPERATOR · needs a target",
                    "plan": "Podaj zadanie dla Operatora: co ma otworzyć, sprawdzić albo zmienić."}
        destructive = _is_destructive(task)
        return {"intent": "operator", "confidence": 1.0, "action": "operator", "task": task,
                "needs_confirmation": False, "destructive": destructive,
                "reason": "explicit /operator",
                "label": "OPERATOR · destructive, needs confirmation" if destructive else "OPERATOR · explicit",
                "plan": _plan(task)}
    bg_explicit = BACKGROUND_PREFIX.match(text)
    if bg_explicit:
        bg_task = bg_explicit.group(1).strip()
        destructive = _is_destructive(bg_task)
        return {
            'intent': 'operator',
            'confidence': 1.0,
            'action': 'operator',
            'task': bg_task,
            'background': True,
            'needs_confirmation': False,
            'destructive': destructive,
            'reason': 'explicit background operator task',
            'label': 'OPERATOR · background' if not destructive else 'OPERATOR · destructive, needs confirmation',
            'plan': 'Uruchomię zadanie równolegle w tle (Background Lane) bez blokowania rozmowy i głównej kolejki.',
        }
    call = OPERATOR_CALL.match(text)
    if call:
        task = call.group(1).strip()
        task = re.sub(r"^(?:że|ze|żeby|zeby|aby|i|and|to|do|for)\s+", "", task, flags=re.I).strip()
        filler_words = TARGETLESS | {"bro", "man", "ziomek", "proszę", "prosze", "please", "teraz", "now", "already", "już", "juz"}
        is_filler = not task or task.casefold().strip(".!?") in filler_words
        if is_filler:
            return {"intent": "operator", "confidence": 0.6, "action": "clarify", "task": text,
                    "needs_confirmation": True, "reason": "operator named without a task",
                    "label": "OPERATOR · needs a target",
                    "plan": "Podaj zadanie dla Operatora: co ma otworzyć, sprawdzić albo zmienić."}
        destructive = _is_destructive(task)
        return {"intent": "operator", "confidence": 0.9, "action": "operator", "task": task,
                "needs_confirmation": False, "destructive": destructive,
                "reason": "explicit operator call",
                "label": "OPERATOR · destructive, needs confirmation" if destructive else "OPERATOR · explicit call",
                "plan": _plan(task)}
    if re.match(r"^teardown\b", text, re.I):
        return {"intent": "teardown", "confidence": 1.0, "action": "teardown", "task": text,
                "needs_confirmation": False, "reason": "teardown intent", "label": "TEARDOWN"}
    if re.match(r"^(?:remember|zapamiętaj|zapamietaj|/remember)\b", text, re.I):
        return {"intent": "memory", "confidence": 1.0, "action": "memory", "task": text,
                "needs_confirmation": False, "reason": "memory command", "label": "MEMORY"}
    if re.match(r"^(?:przypomnij|przypominam)\b", text, re.I):
        return {"intent": "memory", "confidence": 1.0, "action": "memory", "task": text,
                "needs_confirmation": False, "reason": "reminder intent", "label": "REMINDER"}
    if re.match(
        r"^(?:remind\s+me|/remind)\b|"
        r"^(?:pokaż|pokaz|wypisz|list|show)\s+(?:moje\s+|my\s+|wszystkie\s+|zaległe\s+|zalegle\s+)(?:przypomnieni\w*|reminders?)\b",
        text,
        re.I,
    ):
        return {"intent": "operator", "confidence": 0.95, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": False,
                "reason": "scheduled reminder action",
                "label": "OPERATOR · reminder",
                "plan": "Zapiszę lub sprawdzę przypomnienie w lokalnej bazie Operatora (reminders)."}
    if CAPABILITY_INTENT.match(text):
        return {"intent": "capabilities", "confidence": 1.0, "action": "capabilities", "task": text,
                "needs_confirmation": False, "reason": "capability question",
                "label": "CAPABILITIES · live registry"}
    destructive_text = _is_destructive(text)
    if not NOTES_REFERENCE.search(text) and not destructive_text:
        try:
            import auto_bg as _abg
            _auto_bg_ok, _auto_bg_why = _abg.should_run_in_background(text)
        except Exception:
            _auto_bg_ok, _auto_bg_why = False, ''
        if _auto_bg_ok:
            return {
                'intent': 'operator',
                'confidence': 0.96,
                'action': 'operator',
                'task': _abg.strip_bg_prefix(text),
                'background': True,
                'needs_confirmation': False,
                'destructive': False,
                'reason': f'auto-background ({_auto_bg_why})',
                'label': 'OPERATOR · auto-background',
                'plan': 'Uruchomię to zadanie automatycznie w tle (Background Lane) i pokażę etapy na żywo, nie blokując rozmowy.',
            }
    compound = parse_compound_steps(text)
    if compound:
        lanes = {item["lane"] for item in compound}
        needs_operator = ("operator" in lanes and len(lanes - {"general"}) >= 2)
        if needs_operator:
            phases = [item["step"] for item in compound]
            is_dest = any(item["destructive"] for item in compound) or destructive_text
            lane_summary = " → ".join(item["lane"].upper() for item in compound)
            return {
                "intent": "operator",
                "confidence": 0.94,
                "action": "operator",
                "task": text,
                "compound": True,
                "phases": phases,
                "lanes": [item["lane"] for item in compound],
                "needs_confirmation": False,
                "destructive": is_dest,
                "reason": f"compound multi-step request ({lane_summary})",
                "label": ("OPERATOR · destructive, needs confirmation"
                          if is_dest else f"OPERATOR · pipeline ({len(phases)} steps)"),
                "plan": f"Wykonam wieloetapowy plan ({len(phases)} kroków: {lane_summary}): "
                        + " → ".join(phases[:4]),
            }
    if WORKSPACE_DEICTIC_RE.search(text) and not NOTES_REFERENCE.search(text):
        enriched_task, ws_snap = _enrich_with_workspace(text)
        needs_clip = bool(re.search(r"\b(?:schowek|schowka|schowku|clipboard)\b", text, re.I))
        return {
            "intent": "operator",
            "confidence": 0.91,
            "action": "operator",
            "task": enriched_task,
            "raw_task": text,
            "workspace_bound": True,
            "workspace_clipboard_hint": needs_clip,
            "workspace_summary": ws_snap.get("summary") if isinstance(ws_snap, dict) else None,
            "needs_confirmation": False,
            "destructive": destructive_text,
            "reason": "deictic reference bound to active workspace context",
            "label": ("OPERATOR · destructive, needs confirmation"
                      if destructive_text else "OPERATOR · workspace context"),
            "plan": "Pobiorę bieżący kontekst pulpitu/projektu (workspace_context) i wykonam polecenie na aktywnym obiekcie.",
        }
    if SYSTEM_STATE.search(text) and MACHINE_MARKER.search(text) and not NOTES_REFERENCE.search(text):
        # "Ile wolnego miejsca na dysku mam teraz?" is a read of this machine,
        # answered by the Operator's system tools, not by the chat brain.
        return {"intent": "operator", "confidence": 0.8, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "system-state question about this machine",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text else "OPERATOR · system read",
                "plan": "Odczytam stan systemu narzędziami Operatora; nic nie zmienię bez approvalu."}
    if CODE_OBJECT.search(text) and CODE_ACTION.search(text) and not NOTES_REFERENCE.search(text):
        return {"intent": "operator", "confidence": 0.95, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "code inspection, audit or upgrade request",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text else "OPERATOR · code scan",
                "plan": _domain_plan(text)}
    if AGENT_OBJECT.search(text) and AGENT_ACTION.search(text) and not NOTES_REFERENCE.search(text):
        return {"intent": "operator", "confidence": 0.95, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "external agents test or status request",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text else "OPERATOR · agent action",
                "plan": _domain_plan(text)}
    if SERVICE_OBJECT.search(text) and SERVICE_ACTION.search(text) and not NOTES_REFERENCE.search(text):
        return {"intent": "operator", "confidence": 0.95, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "system service or process inspection request",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text else "OPERATOR · service action",
                "plan": _domain_plan(text)}
    if DEV_OBJECT.search(text) and DEV_ACTION.search(text) and not NOTES_REFERENCE.search(text):
        return {"intent": "operator", "confidence": 0.95, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "software development, build, or repair request",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text else "OPERATOR · dev action",
                "plan": _domain_plan(text)}
    task_like = bool(TASK_LIKE_RE.search(text))
    if CREATIVE_TASK.match(text) and not task_like and not COMPUTER_OBJECT.search(text):
        # Creative writing and translation are chat answers, not Operator
        # jobs. A note reference still belongs to the grounded notes lane.
        if NOTES_REFERENCE.search(text):
            return {"intent": "notes", "confidence": 0.75, "action": "notes", "task": text,
                    "needs_confirmation": False,
                    "reason": "creative task grounded in notes", "label": "NOTES · note task"}
        return {"intent": "question", "confidence": 0.7, "action": "general", "task": text,
                "needs_confirmation": False,
                "reason": "creative/translation task", "label": "CHAT · writing task"}
    lookup = LOOKUP_TASK.match(text)
    if lookup:
        remainder = re.findall(r"[^\W_]+", text[lookup.end():], re.UNICODE)
        if all(word.casefold() in TARGETLESS for word in remainder):
            return {"intent": "operator", "confidence": 0.45, "action": "clarify", "task": text,
                    "needs_confirmation": True, "reason": "lookup without a target",
                    "label": "OPERATOR · needs a target",
                    "plan": "Podaj obiekt: adres strony, ścieżkę pliku albo treść zadania."}
        if NOTES_REFERENCE.search(text):
            return {"intent": "notes", "confidence": 0.8, "action": "notes", "task": text,
                    "needs_confirmation": False,
                    "reason": "lookup in notes", "label": "NOTES · lookup"}
        if not task_like and not COMPUTER_OBJECT.search(text) and not SYSTEM_STATE.search(text):
            if WEB_RE.search(text) or WEB_LOOKUP.search(text):
                return {"intent": "web", "confidence": 0.75, "action": "web", "task": text,
                        "needs_confirmation": False,
                        "reason": "find/check needs current public sources",
                        "label": "WEB RESEARCH"}
            # "sprawdź czy to prawda" / "znajdź błąd" are questions the chat
            # brain can answer; they do not need a computer tool run.
            return {"intent": "question" if "?" in text else "general",
                    "confidence": 0.6, "action": "general", "task": text,
                    "needs_confirmation": False,
                    "reason": "lookup without a computer object", "label": "CHAT · lookup"}
    match = OPERATOR_RE.match(text)
    if match:
        # A bare verb ("zrób") or a placeholder object ("zrób coś") is not
        # enough; "sprawdź stronę" and "uruchom testy" name a real target.
        remainder = re.findall(r"[^\W_]+", text[match.end():], re.UNICODE)
        # A dative pronoun can precede the real object ("znajdź mi hotel"),
        # so filter every placeholder token, not only the first one.
        has_target = any(word.casefold() not in TARGETLESS for word in remainder)
        vague = bool(VAGUE.match(text)) and not has_target and not task_like
        if vague:
            return {"intent": "operator", "confidence": 0.45, "action": "clarify", "task": text,
                    "needs_confirmation": True, "reason": "imperative without a target",
                    "label": "OPERATOR · needs a target", "plan": "Podaj obiekt: adres strony, ścieżkę pliku albo treść zadania."}
        confidence = 0.92 if task_like else 0.78
        return {"intent": "operator", "confidence": confidence, "action": "operator", "task": text,
                "needs_confirmation": False, "destructive": destructive_text,
                "reason": "imperative action request",
                "label": "OPERATOR · destructive, needs confirmation" if destructive_text
                else "OPERATOR · plan ready", "plan": _plan(text)}
    if WEB_RE.search(text):
        return {"intent": "web", "confidence": 0.8, "action": "web", "task": text,
                "needs_confirmation": False, "reason": "price/current fact intent", "label": "WEB RESEARCH"}
    if text.endswith("?") or re.match(r"^(?:co|kto|gdzie|kiedy|dlaczego|jak|czy|ile|what|who|where|when|why|how|is|are|do|does)\b", text, re.I):
        return {"intent": "question", "confidence": 0.7, "action": "notes", "task": text,
                "needs_confirmation": False, "reason": "question intent", "label": "NOTES → GENERAL"}
    return {"intent": "general", "confidence": 0.55, "action": "general", "task": text,
            "needs_confirmation": False, "reason": "conversational/general", "label": "GENERAL"}


def _plan(text: str) -> str:
    domain_plan = _domain_plan(text)
    if domain_plan:
        return domain_plan
    if re.search(r"https?://", text):
        return "Otworzę stronę w przeglądarce Operatora i sprawdzę wynik; akcje wymagające zgody zatrzymają się na approvalu."
    if re.search(r"\.(?:txt|pdf|docx|xlsx|pptx|csv|json|png|jpg|zip)\b", text, re.I):
        return "Użyję narzędzi plikowych Operatora; zapis lub usunięcie będzie wymagało zatwierdzenia."
    return "Przekażę zadanie do Operatora; każda akcja z side effectem przejdzie przez approval."

