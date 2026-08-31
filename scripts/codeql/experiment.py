"""Fixed experiment configuration for the reproducible CodeQL pipeline."""

from __future__ import annotations

EXPECTED_CODEQL_VERSION = "2.23.2"
DEFAULT_QUERY_SUITE = "code-scanning"

QUERY_PACKS = {
    "cpp": ("codeql/cpp-queries", "cpp"),
    "csharp": ("codeql/csharp-queries", "csharp"),
    "go": ("codeql/go-queries", "go"),
    "java-kotlin": ("codeql/java-queries", "java"),
    "javascript-typescript": ("codeql/javascript-queries", "javascript"),
    "python": ("codeql/python-queries", "python"),
    "ruby": ("codeql/ruby-queries", "ruby"),
    "swift": ("codeql/swift-queries", "swift"),
}


def default_build_mode(language: str, codeql_language: str) -> str:
    """Return the CodeQL database build mode for the experiment language."""
    if codeql_language == "go":
        # CodeQL has no build-mode=none for Go; autobuild is Go's robust
        # default and handles module detection / go generate better than a
        # bare `go build ./...`.
        return "autobuild"
    return "none"


def default_build_command(language: str, codeql_language: str) -> str:
    return ""


def query_spec(codeql_language: str, suite: str = DEFAULT_QUERY_SUITE) -> str:
    try:
        pack, prefix = QUERY_PACKS[codeql_language]
    except KeyError as exc:
        raise ValueError(f"没有查询套件映射: {codeql_language}") from exc
    return f"{pack}:codeql-suites/{prefix}-{suite}.qls"
