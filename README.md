# JavaScript Secret Scanner

A Python-based security tool that crawls websites and scans JavaScript code for exposed secrets such as API keys, tokens, and credentials.

The scanner recursively crawls a target website, collects both external and inline JavaScript, applies multiple detection rules, and reports potential secret exposures with confidence scores and contextual code snippets.

---

## Features

- Recursive website crawling
- External JavaScript discovery
- Inline JavaScript scanning
- Multiple secret detection rules
- Confidence scoring to reduce false positives
- Duplicate finding suppression
- Context extraction around each finding
- Minified JavaScript support
- Recursive internal link crawling
