# Ghost Data Still Exists audit agent

Run from the repository root:

```powershell
python code\main.py
python code\evaluation\main.py
```

The implementation uses Pandas, exact and historical identity links, audit-time filtering,
and deterministic parsing of text, JSON, SQL, logs, PDFs, and images. PDF/image extraction
is optional; unreadable artifacts are reported rather than treated as absent. Model calls
are disabled by default because this corpus is deterministic and no credentials are needed.

Optional Groq interpretation is enabled only with `LLM_ENABLED=1`, `GROQ_API_KEY`, and
`GROQ_MODEL`. Groq output is schema-validated and citation-filtered; it never determines
policy status or remediation ordering. Copy `.env.example` to `.env` for local configuration.
