"""Review the Git index for private files and common credential material.

This is a narrow pre-publication check, not a general secret-scanning guarantee.
Only staged filenames are reported, never credential keys or matched values.
"""

import io
from pathlib import Path
import re
import subprocess
import sys
import zipfile


def git_bytes(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments])


def check_index() -> list[str]:
    root = Path(git_bytes("rev-parse", "--show-toplevel").decode().strip())
    paths = git_bytes("ls-files", "-z").decode().split("\0")
    failures: list[str] = []
    local_secrets: set[bytes] = set()
    environment = root / ".env"
    if environment.is_file():
        for line in environment.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            value = value.strip().strip("\"'")
            if (separator and re.search(r"SECRET|KEY|TOKEN|PASSWORD|PEPPER", key)
                    and len(value) >= 16 and not value.startswith("change-this-")):
                local_secrets.add(value.encode())
    forbidden = re.compile(
        r"(^private/|(^|/)\.env$|(^|/)(node_modules|output|\.venv|bin|obj)/|"
        r"\.(pem|key|pfx)$)", re.IGNORECASE,
    )
    token_patterns = [
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
        re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    ]
    for path in filter(None, paths):
        if forbidden.search(path):
            failures.append(f"Private or generated path in index: {path}")
        content = git_bytes("show", f":{path}")
        if path.endswith(".pptx"):
            with zipfile.ZipFile(io.BytesIO(content)) as deck:
                content = b"\n".join(deck.read(name) for name in deck.namelist()
                                     if name.endswith(".xml"))
        for secret in local_secrets:
            if secret in content:
                failures.append(f"Local credential found in: {path}")
        if any(pattern.search(content) for pattern in token_patterns):
            failures.append(f"Possible token or private key in: {path}")
    return failures


if __name__ == "__main__":
    problems = check_index()
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        sys.exit(1)
    print("PASS: index excludes private/generated paths; no local .env credentials "
          "or common token/private-key patterns found.")
