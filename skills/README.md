# Jarvis skills

Each subdirectory contains a `SKILL.md` with YAML frontmatter:

```markdown
---
name: kebab-case-name
description: One sentence that starts with "Use when ...".
---

# Instructions

Steps, pitfalls and verification the Operator should follow.
```

Bundled skills live here. Private skills can live in `~/.jarvis-tools/skills`.
Jarvis can list, search and read skills; reading a skill never executes code.
