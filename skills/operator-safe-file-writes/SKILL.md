---
name: operator-safe-file-writes
description: Use when the Operator edits or deletes files; preserve backups and verify the actual effect.
---

# Safe file changes

1. Read the file before changing it; never overwrite from a guessed shape.
2. Prefer a targeted patch over a full rewrite.
3. `write_file` already creates a backup; confirm the returned backup path.
4. After writing, read back the target or compare its hash. A successful tool
   call is not proof that the change is what the user asked for.
5. For deletion, use `delete_path` so the path is recoverable through undo.
6. If the target is outside the home/temp/media boundaries, stop and ask.
7. Never write secrets, API keys or session tokens into a note.
