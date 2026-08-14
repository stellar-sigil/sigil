#!/usr/bin/env python3
"""Fail if a crate declares a dependency its source never imports.

A manifest listing a library the code does not call is a claim the repository
cannot back. This runs in CI so the claim cannot drift back in.

Dev-dependencies are checked against tests as well as src.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def declared(manifest_text, section):
    """Dependency names under [section], ignoring inline tables and comments."""
    names = []
    current = None
    for line in manifest_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            current = line.strip("[]")
            continue
        if current != section or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().strip('"')
        # `serde.workspace = true` declares serde, not serde.workspace
        name = key.split(".", 1)[0] if "." in key else key
        if name and not name.startswith("."):
            names.append(name)
    return names


def strip_cfg_test(text):
    """Remove #[cfg(test)] items.

    A dependency used only by a test module inside src/lib.rs is not a
    dependency of the shipping library, and this is the case the guard exists
    to catch.
    """
    out = []
    i = 0
    while True:
        marker = text.find("#[cfg(test)]", i)
        if marker == -1:
            out.append(text[i:])
            return "".join(out)
        out.append(text[i:marker])
        brace = text.find("{", marker)
        if brace == -1:
            return "".join(out)
        depth = 0
        for j in range(brace, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    i = j + 1
                    break
        else:
            return "".join(out)


def sources(crate_dir, include_tests):
    paths = list((crate_dir / "src").rglob("*.rs"))
    text = "\n".join(p.read_text() for p in paths)
    if not include_tests:
        return strip_cfg_test(text)
    tests = crate_dir / "tests"
    if tests.is_dir():
        text += "\n" + "\n".join(p.read_text() for p in tests.rglob("*.rs"))
    return text


def used(text, dep):
    ident = dep.replace("-", "_")
    return re.search(rf"\b{re.escape(ident)}\s*::", text) or re.search(
        rf"^\s*use\s+{re.escape(ident)}\b", text, re.M
    )


def main():
    failures = []
    for manifest in ROOT.rglob("Cargo.toml"):
        if "target" in manifest.parts or manifest.parent == ROOT:
            continue
        text = manifest.read_text()
        crate = manifest.parent
        rel = manifest.relative_to(ROOT)

        for section, include_tests in (("dependencies", False), ("dev-dependencies", True)):
            body = sources(crate, include_tests=True if section == "dev-dependencies" else False)
            for dep in declared(text, section):
                if not used(body, dep):
                    where = "src" if section == "dependencies" else "src or tests"
                    failures.append(f"{rel}: [{section}] '{dep}' is never imported in {where}")

    if failures:
        print("phantom dependencies found:\n")
        for f in failures:
            print(f"  {f}")
        print("\nRemove it, or move it to dev-dependencies if only tests use it.")
        return 1

    print("no phantom dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
