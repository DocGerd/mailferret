"""T-10: write and SMTP stay interface-only and unimported (A§2.5)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
PKG = SRC / "mailferret"
GUARDED_DIRS = (PKG / "write", PKG / "smtp")
GUARDED = ("mailferret.write", "mailferret.smtp")
EXPECTED_ENTRIES = {"__init__.py", "api.py"}
ALLOWED_IMPORTS = {"__future__", "typing", "collections.abc"}
INTERFACE_BASES = {"Protocol"}
ALLOWED_DECORATORS = {"runtime_checkable"}


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
    return _name(base.value if isinstance(base, ast.Subscript) else base)


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


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _inert_subscript(node: ast.expr) -> bool:
    if isinstance(node, ast.Name | ast.Constant):
        return True
    if isinstance(node, ast.Tuple):
        return all(_inert_subscript(e) for e in node.elts)
    return False


def _check_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    found: list[str] = []
    if node.decorator_list:
        found.append(f"{node.name}: decorator")
    defaults = [*node.args.defaults, *node.args.kw_defaults]
    if not all(d is None or isinstance(d, ast.Constant) for d in defaults):
        found.append(f"{node.name}: non-constant default")
    if not _is_stub(node):
        found.append(f"{node.name}: has a body")
    return found


def _check_class(node: ast.ClassDef) -> list[str]:
    found: list[str] = []
    if not node.bases:
        found.append(f"{node.name}: no base")
    for base in node.bases:
        if _base_name(base) not in INTERFACE_BASES:
            found.append(f"{node.name}: base {_base_name(base)!r}")
        if isinstance(base, ast.Subscript) and not _inert_subscript(base.slice):
            found.append(f"{node.name}: non-inert base subscript")
    if node.keywords:
        found.append(f"{node.name}: class keyword")
    for dec in node.decorator_list:
        if _name(dec) not in ALLOWED_DECORATORS:
            found.append(f"{node.name}: decorator")
    for member in node.body:
        if _is_str_const(member):
            continue
        if isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
            found.extend(_check_function(member))
        else:
            found.append(f"{node.name}: member {type(member).__name__}")
    return found


def implementation_violations(source: str, *, docstring_only: bool = False) -> list[str]:
    """Reasons `source` is not interface-only; `docstring_only` is for `__init__.py`."""
    tree = ast.parse(source)
    found = [type(n).__name__ for n in ast.walk(tree) if isinstance(n, ast.Call | ast.Lambda)]
    for node in tree.body:
        if _is_str_const(node):
            continue
        if docstring_only:
            found.append(f"__init__: {type(node).__name__}")
        elif isinstance(node, ast.Import):
            if not {a.name for a in node.names} <= ALLOWED_IMPORTS:
                found.append(f"import {ast.dump(node)}")
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module not in ALLOWED_IMPORTS:
                found.append(f"import {ast.dump(node)}")
        elif isinstance(node, ast.ClassDef):
            found.extend(_check_class(node))
        else:
            found.append(f"top-level {type(node).__name__}")
    return found


def package_entries(pkg: Path) -> set[str]:
    return {
        p.relative_to(pkg).as_posix()
        for p in pkg.rglob("*")
        if "__pycache__" not in p.relative_to(pkg).parts
    }


def package_modules(pkg: Path) -> list[Path]:
    return sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)


@pytest.mark.parametrize("pkg", GUARDED_DIRS, ids=lambda p: p.name)
def test_guarded_packages_contain_only_expected_entries(pkg: Path) -> None:
    assert package_entries(pkg) == EXPECTED_ENTRIES


@pytest.mark.parametrize("pkg", GUARDED_DIRS, ids=lambda p: p.name)
def test_guarded_modules_have_no_implementation(pkg: Path) -> None:
    for path in package_modules(pkg):
        found = implementation_violations(
            path.read_text(), docstring_only=path.name == "__init__.py"
        )
        assert not found, f"{path.relative_to(SRC)}: {found}"


@pytest.mark.parametrize("pkg", GUARDED_DIRS, ids=lambda p: p.name)
def test_guarded_packages_import_nothing_internal(pkg: Path) -> None:
    for path in package_modules(pkg):
        module, is_package = _module_of(path)
        found = imported_modules(path.read_text(), module, is_package)
        assert not {m for m in found if m.split(".")[0] == "mailferret"}, path.name


def test_nothing_else_imports_write_or_smtp() -> None:
    offenders: dict[str, set[str]] = {}
    for path in PKG.rglob("*.py"):
        if any(d in path.parents for d in GUARDED_DIRS):
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


GOOD = (
    "from __future__ import annotations\n"
    "from typing import Protocol, runtime_checkable\n"
    "@runtime_checkable\n"
    "class P(Protocol):\n"
    "    def f(self, x: int = 0, *, y: str | None = None) -> None: ...\n"
)


@pytest.mark.parametrize(
    "source",
    [
        GOOD,
        "from typing import Protocol\nclass P(Protocol[int, 'X']):\n    async def f(self): ...\n",
    ],
)
def test_accepts_interface_only_source(source: str) -> None:
    assert implementation_violations(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import os\n",
        "x = 1\n",
        "from abc import ABC\n",
        "from typing import Protocol\nclass P(ABC): ...\n",
        "from typing import Protocol\nclass P(Protocol, metaclass=type): ...\n",
        "from typing import Protocol\nclass P(Protocol[__import__('os')]):\n    def f(self): ...\n",
        "from typing import Protocol\nclass P(Protocol[int.real]):\n    def f(self): ...\n",
        "from typing import Protocol\nclass P(Protocol):\n    x: int\n",
        "from typing import Protocol\nclass P(Protocol):\n    @staticmethod\n    def f(): ...\n",
        "from typing import Protocol\nclass P(Protocol):\n"
        "    @(lambda f: f)\n    def f(self): ...\n",
        "from typing import Protocol\nclass P(Protocol):\n"
        "    def f(self, x=__import__('os')): ...\n",
        "from typing import Protocol\nclass P(Protocol):\n    def f(self, *, x=[]): ...\n",
        "from typing import Protocol\nclass P(Protocol):\n    def f(self):\n        return 1\n",
        "from typing import Protocol\n@print\nclass P(Protocol): ...\n",
    ],
)
def test_rejects_implementation(source: str) -> None:
    assert implementation_violations(source)


@pytest.mark.parametrize(
    "source", ["import os\n", "x = __import__('os')\n", "from typing import Any\n"]
)
def test_init_must_hold_only_a_docstring(source: str) -> None:
    assert implementation_violations(source, docstring_only=True)
    assert not implementation_violations('"""Doc."""\n', docstring_only=True)


def test_entries_reject_subpackage_and_stray_files(tmp_path: Path) -> None:
    for name in ("__init__.py", "api.py"):
        (tmp_path / name).write_text('"""Doc."""\n')
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "api.cpython-312.pyc").write_bytes(b"")
    assert package_entries(tmp_path) == EXPECTED_ENTRIES

    (tmp_path / "impl").mkdir()
    (tmp_path / "impl" / "ops.py").write_text("import os\n")
    assert package_entries(tmp_path) != EXPECTED_ENTRIES
    assert [p.name for p in package_modules(tmp_path)] == ["__init__.py", "api.py", "ops.py"]
    assert implementation_violations((tmp_path / "impl" / "ops.py").read_text())

    (tmp_path / "impl" / "ops.py").unlink()
    (tmp_path / "impl").rmdir()
    (tmp_path / "data.json").write_text("{}")
    assert package_entries(tmp_path) != EXPECTED_ENTRIES
