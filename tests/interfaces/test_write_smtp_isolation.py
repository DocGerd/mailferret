"""T-10: write and SMTP stay interface-only and unimported (A§2.5)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
PKG = SRC / "mailferret"
GUARDED_DIRS = (PKG / "write", PKG / "smtp")
GUARDED = ("mailferret.write", "mailferret.smtp")
API_FILES = [d / "api.py" for d in GUARDED_DIRS]
ALLOWED_IMPORTS = {"__future__", "typing", "collections.abc"}
INTERFACE_BASES = {"Protocol", "ABC"}


def _is_str_const(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _is_stub(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = node.body[1:] if _is_str_const(node.body[0]) else node.body
    return (
        len(body) == 1
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and body[0].value.value is Ellipsis
    )


def _base_name(base: ast.expr) -> str:
    node = base.value if isinstance(base, ast.Subscript) else base
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def imported_modules(source: str, module: str, is_package: bool = False) -> set[str]:
    """Absolute names a module imports, relative imports resolved against `module`."""
    pkg = module.split(".")
    if not is_package:
        pkg.pop()
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = pkg[: len(pkg) - (node.level - 1)] if node.level else []
            name = ".".join([*base, *([node.module] if node.module else [])])
            found.add(name)
            found.update(f"{name}.{alias.name}" for alias in node.names)
    return found


def _module_of(path: Path) -> tuple[str, bool]:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _is_guarded(name: str) -> bool:
    return any(name == g or name.startswith(g + ".") for g in GUARDED)


@pytest.mark.parametrize("path", API_FILES, ids=lambda p: p.parent.name)
def test_api_module_has_no_implementation(path: Path) -> None:
    for node in ast.parse(path.read_text()).body:
        if _is_str_const(node):
            continue
        if isinstance(node, ast.Import):
            assert {a.name for a in node.names} <= ALLOWED_IMPORTS, ast.dump(node)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module in ALLOWED_IMPORTS, ast.dump(node)
        elif isinstance(node, ast.ClassDef):
            assert node.bases
            assert all(_base_name(b) in INTERFACE_BASES for b in node.bases)
            assert all(k.arg == "metaclass" for k in node.keywords)
            for member in node.body:
                if _is_str_const(member):
                    continue
                assert isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
                assert _is_stub(member), f"{node.name}.{member.name} has a body"
        else:
            pytest.fail(f"{path.name}: disallowed top-level {type(node).__name__}")


def test_guarded_packages_contain_only_expected_files() -> None:
    for pkg in GUARDED_DIRS:
        assert {p.name for p in pkg.glob("*.py")} == {"__init__.py", "api.py"}


def test_guarded_packages_import_nothing_internal() -> None:
    for pkg in GUARDED_DIRS:
        for path in pkg.glob("*.py"):
            module, is_package = _module_of(path)
            found = imported_modules(path.read_text(), module, is_package)
            assert not {m for m in found if m.split(".")[0] == "mailferret"}, path.name


def test_nothing_else_imports_write_or_smtp() -> None:
    offenders: dict[str, set[str]] = {}
    for path in PKG.rglob("*.py"):
        if path.parent in GUARDED_DIRS:
            continue
        module, is_package = _module_of(path)
        hits = {m for m in imported_modules(path.read_text(), module, is_package) if _is_guarded(m)}
        if hits:
            offenders[str(path.relative_to(SRC))] = hits
    assert not offenders


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import mailferret.write.api", "mailferret.write.api"),
        ("from mailferret import smtp", "mailferret.smtp"),
        ("from ..write import api", "mailferret.write.api"),
        ("from .. import smtp", "mailferret.smtp"),
        ("from .. import write", "mailferret.write"),
    ],
)
def test_scanner_resolves_imports(source: str, expected: str) -> None:
    found = imported_modules(source, "mailferret.server.x")
    assert expected in found
    assert any(_is_guarded(m) for m in found)


def test_stub_check_rejects_bodies() -> None:
    impl = ast.parse("def f(self) -> None:\n    return None\n").body[0]
    stub = ast.parse("def f(self) -> None: ...\n").body[0]
    assert isinstance(impl, ast.FunctionDef) and isinstance(stub, ast.FunctionDef)
    assert not _is_stub(impl)
    assert _is_stub(stub)
