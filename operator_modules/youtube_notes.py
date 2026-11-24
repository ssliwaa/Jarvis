"""Preview YouTube transcripts as untrusted data; never write to the vault."""

import re
from urllib.parse import parse_qs, urlsplit


def video_id(url):
    """Accept only HTTPS YouTube video URLs; fetch by ID, not caller URL."""
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Invalid YouTube URL")
    try:
        parsed = urlsplit(url)
        host = parsed.netloc.lower()
        if parsed.scheme.lower() != "https" or host not in {
            "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be", "www.youtu.be"
        }:
            raise ValueError("Invalid YouTube URL")
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=50)
        if host in {"youtu.be", "www.youtu.be"}:
            identifier = parsed.path[1:] if parsed.path.startswith("/") else ""
            if "v" in query:
                raise ValueError("Ambiguous video ID")
        elif parsed.path == "/watch":
            values = query.get("v", [])
            identifier = values[0] if len(values) == 1 else ""
        else:
            match = re.fullmatch(r"/(?:shorts|embed|live)/([A-Za-z0-9_-]{11})", parsed.path)
            identifier = match.group(1) if match else ""
            if "v" in query:
                raise ValueError("Ambiguous video ID")
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", identifier):
            raise ValueError("Invalid video ID")
        return identifier
    except (ValueError, UnicodeError):
        raise ValueError("Invalid YouTube URL or video ID") from None


def youtube_notes(arguments, context=None):
    return {"ok": False, "error": "Transcript preview is not available yet."}


TOOL = {
    "name": "youtube_notes",
    "description": "Preview a YouTube transcript. This tool does not save notes.",
    "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}},
    "handler": youtube_notes,
    "approval": False,
}
