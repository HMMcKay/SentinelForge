"""Check the static project page without installing build dependencies."""

from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.links: list[str] = []
        self.resources: list[str] = []
        self.stages: list[str] = []
        self.images: list[dict[str, str | None]] = []
        self.headings = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if identifier := attributes.get("id"):
            self.ids.append(identifier)
        if tag == "h1":
            self.headings += 1
        if tag == "a" and attributes.get("href"):
            self.links.append(str(attributes["href"]))
        if tag == "link" and attributes.get("href"):
            self.resources.append(str(attributes["href"]))
        if tag in {"img", "script"} and attributes.get("src"):
            self.resources.append(str(attributes["src"]))
        if image := attributes.get("data-image"):
            self.resources.append(image)
        if stage := attributes.get("data-stage"):
            self.stages.append(stage)
        if tag == "img":
            self.images.append(attributes)


def check_page() -> list[str]:
    root = Path(__file__).resolve().parents[1] / "docs" / "site"
    source = (root / "index.html").read_text(encoding="utf-8")
    parser = PageParser()
    parser.feed(source)
    failures: list[str] = []
    if parser.headings != 1:
        failures.append("The page must have exactly one h1.")
    if len(set(parser.ids)) != len(parser.ids):
        failures.append("Duplicate HTML IDs.")
    expected = {"simulate", "collect", "normalize", "detect", "investigate", "verify"}
    if set(parser.stages) != expected or len(parser.stages) != 6:
        failures.append("Workflow must expose all six unique stages.")
    for link in parser.links:
        parsed = urlsplit(link)
        if not parsed.scheme and not parsed.path and parsed.fragment not in parser.ids:
            failures.append(f"Missing anchor: {link}")
    for resource in parser.resources:
        parsed = urlsplit(resource)
        if parsed.scheme or parsed.netloc:
            failures.append(f"Site resources must be local: {resource}")
            continue
        if parsed.path.startswith("/"):
            failures.append(f"Root-relative resource breaks repository subpaths: {resource}")
        resolved = (root / unquote(parsed.path)).resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            failures.append(f"Missing or out-of-scope resource: {resource}")
    for image in parser.images:
        if "alt" not in image:
            failures.append("Image without alt attribute.")
    for name in ("sentinelforge-overview.png", "sentinelforge-timeline.png"):
        if (root / "assets" / name).read_bytes() != (root.parent / "assets" / name).read_bytes():
            failures.append(f"Screenshot differs from repository original: {name}")
    script = (root / "site.js").read_text(encoding="utf-8")
    for identifier in re.findall(r"getElementById\('([^']+)'\)", script):
        if identifier not in parser.ids:
            failures.append(f"JavaScript references missing ID: {identifier}")
    if "innerHTML" in script or "eval(" in script:
        failures.append("Use text-only DOM updates, not HTML injection or eval.")
    if not (root / ".nojekyll").is_file():
        failures.append("Missing .nojekyll deployment marker.")
    return failures


if __name__ == "__main__":
    problems = check_page()
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        sys.exit(1)
    print("PASS: page anchors, workflow stages, local resources, original screenshots, "
          "DOM references, and subpath-safe deployment.")
