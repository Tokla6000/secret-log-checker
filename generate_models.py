from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable


SOURCE_KEYWORDS = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "credential",
    "private_key",
    "config",
)

SOURCE_EXCLUDED_HINTS = (
    "non_secret",
    "safe",
)

SANITIZER_KEYWORDS = (
    "mask",
    "redact",
    "hash",
    "sanitize",
    "anonymize",
    "scrub",
)

INPUT_NAME_TOKENS = {
    "args",
    "body",
    "cookie",
    "cookies",
    "data",
    "form",
    "header",
    "headers",
    "json",
    "param",
    "params",
    "payload",
    "query",
    "req",
    "request",
}

SENSITIVE_KEY_TOKENS = {
    "pass",
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "apikey",
    "api_key",
    "credential",
    "privatekey",
    "private_key",
    "accesskey",
    "access_key",
}

SENSITIVE_KEY_PATTERN = re.compile(r"[^a-z0-9]+")
INPUT_NAME_PATTERN = re.compile(r"[^a-z0-9]+")

BENCHMARK_CASES_ROOT = Path("benchmarks/cases")
SCAN_ROOTS = (BENCHMARK_CASES_ROOT,)
BASE_MODELS_PATH = Path("pysa/models/base_models.pysa")
GENERATED_MODELS_PATH = Path("pysa/models/generated_models.pysa")
MERGED_MODELS_PATH = Path("pysa/models/models.pysa")

SKIP_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    "__pycache__",
    "dist",
    "dist-packages",
    "build",
    "site-packages",
    "venv",
}

def collect_attribute_models(tree: ast.AST, module_name: str) -> list[str]:
    attribute_models: list[str] = []

    def visit_body(body: Iterable[ast.stmt], class_prefix: tuple[str, ...] = ()) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                class_name = ".".join((module_name, *class_prefix, node.name))

                for method in node.body:
                    if not isinstance(method, ast.FunctionDef) or method.name != "__init__":
                        continue
                    for stmt in ast.walk(method):
                        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                            continue
                        targets = []
                        if isinstance(stmt, ast.Assign):
                            targets = list(stmt.targets)
                        elif isinstance(stmt, ast.AnnAssign):
                            targets = [stmt.target]

                        for target in targets:
                            if (
                                isinstance(target, ast.Attribute)
                                and isinstance(target.value, ast.Name)
                                and target.value.id == "self"
                                and is_suspicious(target.attr)
                            ):
                                attribute_models.append(
                                    f"{class_name}.{target.attr}: TaintSource[Secret]"
                                )

                visit_body(node.body, class_prefix + (node.name,))

    if isinstance(tree, ast.Module):
        visit_body(tree.body)

    return attribute_models

def module_name_from_path(path: Path, root: Path, module_prefix: str = "") -> str:
    relative_path = path.relative_to(root).with_suffix("")
    parts = [part for part in relative_path.parts if part.isidentifier()]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    module_name = ".".join(parts)
    if module_prefix:
        return f"{module_prefix}.{module_name}" if module_name else module_prefix
    return module_name


def should_skip_path(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in SKIP_DIR_NAMES for part in relative_parts)


def is_suspicious(name: str) -> bool:
    lowered_name = name.lower()
    return any(keyword in lowered_name for keyword in SOURCE_KEYWORDS) and not any(
        excluded_hint in lowered_name for excluded_hint in SOURCE_EXCLUDED_HINTS
    )


def is_sanitizer(name: str) -> bool:
    lowered_name = name.lower()
    return any(keyword in lowered_name for keyword in SANITIZER_KEYWORDS)


def is_sensitive_key(value: str) -> bool:
    lowered = value.lower()
    normalized = SENSITIVE_KEY_PATTERN.sub("", lowered)
    if normalized in SENSITIVE_KEY_TOKENS:
        return True
    for token in SENSITIVE_KEY_PATTERN.split(lowered):
        if token and token in SENSITIVE_KEY_TOKENS:
            return True
    return False


def is_input_like_name(value: str) -> bool:
    lowered = value.lower()
    normalized = INPUT_NAME_PATTERN.sub("", lowered)
    if normalized in INPUT_NAME_TOKENS:
        return True
    for token in INPUT_NAME_PATTERN.split(lowered):
        if token and token in INPUT_NAME_TOKENS:
            return True
    return False


def extract_string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Index):
        return extract_string_literal(node.value)
    return None


def resolve_string_literal(node: ast.AST | None, env: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Index):
        return resolve_string_literal(node.value, env)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = resolve_string_literal(node.left, env)
        right = resolve_string_literal(node.right, env)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                return None
            piece = resolve_string_literal(value, env)
            if piece is None:
                return None
            parts.append(piece)
        return "".join(parts)
    return None


def update_env_from_assign(
    env: dict[str, str],
    targets: list[ast.expr],
    value: ast.AST | None,
) -> None:
    resolved = resolve_string_literal(value, env)
    for target in targets:
        if not isinstance(target, ast.Name):
            continue
        if resolved is None:
            env.pop(target.id, None)
        else:
            env[target.id] = resolved


def collect_module_string_literals(tree: ast.AST) -> dict[str, str]:
    env: dict[str, str] = {}
    if not isinstance(tree, ast.Module):
        return env
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            update_env_from_assign(env, list(statement.targets), statement.value)
        elif isinstance(statement, ast.AnnAssign):
            update_env_from_assign(env, [statement.target], statement.value)
    return env


def collect_module_assigned_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    if not isinstance(tree, ast.Module):
        return names
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name):
                names.add(statement.target.id)
    return names


def extract_root_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return extract_root_name(node.value)
    if isinstance(node, ast.Subscript):
        return extract_root_name(node.value)
    return None


def sensitive_key_from_access(node: ast.AST, env: dict[str, str]) -> str | None:
    if isinstance(node, ast.Subscript):
        key = resolve_string_literal(node.slice, env)
        if key and key.isascii() and is_sensitive_key(key):
            return key
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
        if node.func.attr in {"get", "getlist"}:
            key = resolve_string_literal(node.args[0], env)
            if key and key.isascii() and is_sensitive_key(key):
                return key
    return None


def is_input_like_access(node: ast.AST, env: dict[str, str]) -> bool:
    key = sensitive_key_from_access(node, env)
    if not key:
        return False

    base_node: ast.AST | None = None
    if isinstance(node, ast.Subscript):
        base_node = node.value
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base_node = node.func.value

    if base_node is None:
        return False

    root_name = extract_root_name(base_node)
    if not root_name:
        return False
    return is_input_like_name(root_name)


def input_like_root_name(node: ast.AST, env: dict[str, str]) -> str | None:
    key = sensitive_key_from_access(node, env)
    if not key:
        return None

    base_node: ast.AST | None = None
    if isinstance(node, ast.Subscript):
        base_node = node.value
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base_node = node.func.value

    if base_node is None:
        return None

    root_name = extract_root_name(base_node)
    if not root_name or not is_input_like_name(root_name):
        return None
    return root_name


def collect_sensitive_key_literals(
    tree: ast.AST,
    module_env: dict[str, str],
) -> set[str]:
    keys: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self, env: dict[str, str]) -> None:
            self.env_stack = [env]

        def _env(self) -> dict[str, str]:
            return self.env_stack[-1]

        def visit_Assign(self, node: ast.Assign) -> None:
            update_env_from_assign(self._env(), list(node.targets), node.value)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            update_env_from_assign(self._env(), [node.target], node.value)
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            key = resolve_string_literal(node.slice, self._env())
            if key and key.isascii() and is_sensitive_key(key):
                keys.add(key)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Attribute) and node.args:
                if node.func.attr in {"get", "getlist"}:
                    key = resolve_string_literal(node.args[0], self._env())
                    if key and key.isascii() and is_sensitive_key(key):
                        keys.add(key)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

    if isinstance(tree, ast.Module):
        Visitor(module_env.copy()).visit(tree)
    return keys


def collect_input_sensitive_access(
    tree: ast.AST,
    module_env: dict[str, str],
) -> bool:
    found = False

    class Visitor(ast.NodeVisitor):
        def __init__(self, env: dict[str, str]) -> None:
            self.env_stack = [env]

        def _env(self) -> dict[str, str]:
            return self.env_stack[-1]

        def visit_Assign(self, node: ast.Assign) -> None:
            update_env_from_assign(self._env(), list(node.targets), node.value)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            update_env_from_assign(self._env(), [node.target], node.value)
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            nonlocal found
            if is_input_like_access(node, self._env()):
                found = True
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal found
            if is_input_like_access(node, self._env()):
                found = True
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.env_stack.append(self._env().copy())
            self.generic_visit(node)
            self.env_stack.pop()

    if isinstance(tree, ast.Module):
        Visitor(module_env.copy()).visit(tree)
    return found


def collect_input_sensitive_roots(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_env: dict[str, str],
) -> set[str]:
    roots: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self, env: dict[str, str]) -> None:
            self.env = env

        def visit_Assign(self, assign: ast.Assign) -> None:
            update_env_from_assign(self.env, list(assign.targets), assign.value)
            self.generic_visit(assign)

        def visit_AnnAssign(self, assign: ast.AnnAssign) -> None:
            update_env_from_assign(self.env, [assign.target], assign.value)
            self.generic_visit(assign)

        def visit_Subscript(self, subscript: ast.Subscript) -> None:
            root = input_like_root_name(subscript, self.env)
            if root:
                roots.add(root)
            self.generic_visit(subscript)

        def visit_Call(self, call: ast.Call) -> None:
            root = input_like_root_name(call, self.env)
            if root:
                roots.add(root)
            self.generic_visit(call)

    Visitor(module_env.copy()).visit(node)
    return roots


def collect_global_input_source_names(
    tree: ast.AST,
    module_env: dict[str, str],
    module_assigned_names: set[str],
) -> set[str]:
    names: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def _parameter_names(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> set[str]:
            return {
                *[arg.arg for arg in node.args.posonlyargs],
                *[arg.arg for arg in node.args.args],
                *[arg.arg for arg in node.args.kwonlyargs],
            }

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            input_roots = collect_input_sensitive_roots(node, module_env)
            parameter_names = self._parameter_names(node)
            for root in input_roots.difference(parameter_names):
                if root in module_assigned_names:
                    names.add(root)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            input_roots = collect_input_sensitive_roots(node, module_env)
            parameter_names = self._parameter_names(node)
            for root in input_roots.difference(parameter_names):
                if root in module_assigned_names:
                    names.add(root)
            self.generic_visit(node)

    if isinstance(tree, ast.Module):
        Visitor().visit(tree)
    return names


def function_returns_input_sensitive(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_env: dict[str, str],
) -> bool:
    tainted_vars: set[str] = set()
    returns_sensitive = False
    env = module_env.copy()

    def is_tainted_expr(expr: ast.AST | None) -> bool:
        if expr is None:
            return False
        if is_input_like_access(expr, env):
            return True
        if isinstance(expr, ast.Name):
            return expr.id in tainted_vars
        if isinstance(expr, ast.Attribute):
            return is_tainted_expr(expr.value)
        if isinstance(expr, ast.Subscript):
            return is_tainted_expr(expr.value)
        return False

    def mark_targets(targets: list[ast.expr], value: ast.AST | None) -> None:
        if not is_tainted_expr(value):
            return
        for target in targets:
            if isinstance(target, ast.Name):
                tainted_vars.add(target.id)

    def walk(statements: list[ast.stmt]) -> None:
        nonlocal returns_sensitive
        for statement in statements:
            if returns_sensitive:
                return
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.Assign):
                update_env_from_assign(env, list(statement.targets), statement.value)
                mark_targets(list(statement.targets), statement.value)
                continue
            if isinstance(statement, ast.AnnAssign):
                update_env_from_assign(env, [statement.target], statement.value)
                mark_targets([statement.target], statement.value)
                continue
            if isinstance(statement, ast.Return):
                if is_tainted_expr(statement.value):
                    returns_sensitive = True
                continue
            if isinstance(statement, ast.If):
                walk(statement.body)
                walk(statement.orelse)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                walk(statement.body)
                walk(statement.orelse)
                continue
            if isinstance(statement, (ast.With, ast.AsyncWith)):
                walk(statement.body)
                continue
            if isinstance(statement, ast.Try):
                walk(statement.body)
                walk(statement.orelse)
                walk(statement.finalbody)
                for handler in statement.handlers:
                    walk(handler.body)
                continue

    walk(node.body)
    return returns_sensitive


def build_sanitizer_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    positional = [*args.posonlyargs, *args.args]

    target_name = None
    for argument in positional:
        if argument.arg not in {"self", "cls"}:
            target_name = argument.arg
            break

    if target_name is None and positional:
        target_name = positional[0].arg

    defaults_start = len(positional) - len(args.defaults)
    parts: list[str] = []

    for index, argument in enumerate(positional):
        rendered = argument.arg
        if argument.arg == target_name:
            rendered = f"{argument.arg}: TaintSource[Secret]"
        if index >= defaults_start:
            rendered = f"{rendered}=..."
        parts.append(rendered)

    if args.vararg:
        parts.append(f"*{args.vararg.arg}")
    elif args.kwonlyargs:
        parts.append("*")

    for keyword_only, default in zip(args.kwonlyargs, args.kw_defaults):
        rendered = keyword_only.arg
        if default is not None:
            rendered = f"{rendered}=..."
        parts.append(rendered)

    if args.kwarg:
        parts.append(f"**{args.kwarg.arg}")

    return ", ".join(parts)


def build_source_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_params: set[str],
) -> str:
    args = node.args
    positional = [*args.posonlyargs, *args.args]

    defaults_start = len(positional) - len(args.defaults)
    parts: list[str] = []

    for index, argument in enumerate(positional):
        rendered = argument.arg
        if argument.arg in source_params and argument.arg not in {"self", "cls"}:
            rendered = f"{argument.arg}: TaintSource[Secret]"
        if index >= defaults_start:
            rendered = f"{rendered}=..."
        parts.append(rendered)

    if args.vararg:
        parts.append(f"*{args.vararg.arg}")
    elif args.kwonlyargs:
        parts.append("*")

    for keyword_only, default in zip(args.kwonlyargs, args.kw_defaults):
        rendered = keyword_only.arg
        if keyword_only.arg in source_params and keyword_only.arg not in {"self", "cls"}:
            rendered = f"{keyword_only.arg}: TaintSource[Secret]"
        if default is not None:
            rendered = f"{rendered}=..."
        parts.append(rendered)

    if args.kwarg:
        parts.append(f"**{args.kwarg.arg}")

    return ", ".join(parts)


def build_mapping_access_models(
    sensitive_keys: Iterable[str],
    input_access_found: bool,
) -> list[str]:
    models: list[str] = []
    if not any(sensitive_keys) or not input_access_found:
        return models

    models.append(
        "def dict.__getitem__(self, key, /) -> TaintSource[Secret]: ..."
    )
    models.append(
        "def dict.get(self, key, /) -> TaintSource[Secret]: ..."
    )
    models.append(
        "def dict.get(self, key, default=..., /) -> TaintSource[Secret]: ..."
    )
    models.append(
        "def typing.Mapping.__getitem__(self, key, /) -> TaintSource[Secret]: ..."
    )
    models.append(
        "def typing.Mapping.get(self, key, /) -> TaintSource[Secret]: ..."
    )
    models.append(
        "def typing.Mapping.get(self, key, /, default=...) -> TaintSource[Secret]: ..."
    )
    return models


def collect_function_models(
    tree: ast.AST,
    module_name: str,
    module_env: dict[str, str],
) -> tuple[list[str], list[str]]:
    source_models: list[str] = []
    sanitizer_models: list[str] = []

    def visit_body(body: Iterable[ast.stmt], class_prefix: tuple[str, ...] = ()) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit_body(node.body, class_prefix + (node.name,))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified_name = ".".join((module_name, *class_prefix, node.name))

                if is_sanitizer(node.name):
                    parameters = build_sanitizer_parameters(node)
                    sanitizer_models.append(
                        f"def {qualified_name}({parameters}) -> Sanitize[TaintSource[Secret]]: ..."
                    )
                    continue

                input_roots = collect_input_sensitive_roots(node, module_env)
                if input_roots:
                    parameter_names = {
                        *[arg.arg for arg in node.args.posonlyargs],
                        *[arg.arg for arg in node.args.args],
                        *[arg.arg for arg in node.args.kwonlyargs],
                    }
                    source_params = parameter_names.intersection(input_roots)
                    if source_params:
                        parameters = build_source_parameters(node, source_params)
                        source_models.append(f"def {qualified_name}({parameters}): ...")

                if function_returns_input_sensitive(node, module_env):
                    source_models.append(f"def {qualified_name}() -> TaintSource[Secret]: ...")

                if is_suspicious(node.name):
                    source_models.append(f"def {qualified_name}() -> TaintSource[Secret]: ...")

    if isinstance(tree, ast.Module):
        visit_body(tree.body)

    return source_models, sanitizer_models


def collect_global_models(tree: ast.AST, module_name: str) -> list[str]:
    global_models: list[str] = []

    if not isinstance(tree, ast.Module):
        return global_models

    for node in tree.body:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]

        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if is_suspicious(name):
                global_models.append(f"{module_name}.{name}: TaintSource[Secret]")

    return global_models


def scan_roots(roots: Iterable[Path]) -> tuple[list[str], list[str], list[str], list[str]]:
    generated_source_models: set[str] = set()
    generated_sanitizer_models: set[str] = set()
    generated_global_models: set[str] = set()
    sensitive_keys: set[str] = set()
    input_access_found = False

    for root in roots:
        if not root.exists():
            continue

        module_prefix = ""
        try:
            if root.resolve() == BENCHMARK_CASES_ROOT.resolve():
                module_prefix = "cases"
        except OSError:
            pass

        for path in sorted(root.rglob("*.py")):
            if should_skip_path(path, root):
                continue

            module_name = module_name_from_path(path, root, module_prefix)
            tree = ast.parse(path.read_text(), filename=str(path))
            module_env = collect_module_string_literals(tree)
            module_assigned_names = collect_module_assigned_names(tree)

            sensitive_keys.update(collect_sensitive_key_literals(tree, module_env))
            input_access_found = input_access_found or collect_input_sensitive_access(tree, module_env)

            source_models, sanitizer_models = collect_function_models(
                tree,
                module_name,
                module_env,
            )
            global_models = collect_global_models(tree, module_name)
            attribute_models = collect_attribute_models(tree, module_name)
            
            for model in attribute_models:
                generated_global_models.add(model)
            
            global_input_sources = collect_global_input_source_names(
                tree,
                module_env,
                module_assigned_names,
            )
            for model in source_models:
                generated_source_models.add(model)
            for model in sanitizer_models:
                generated_sanitizer_models.add(model)
            for model in global_models:
                generated_global_models.add(model)
            for name in global_input_sources:
                generated_global_models.add(f"{module_name}.{name}: TaintSource[Secret]")

    mapping_models = build_mapping_access_models(sensitive_keys, input_access_found)

    return (
        sorted(generated_source_models),
        sorted(generated_sanitizer_models),
        sorted(generated_global_models),
        mapping_models,
    )


def write_generated_models(
    source_models: list[str],
    sanitizer_models: list[str],
    global_models: list[str],
    mapping_models: list[str],
    output_path: Path = GENERATED_MODELS_PATH,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "# Auto-generated by generate_models.py. Do not edit manually.",
        "# Source-like names become Secret sources; sanitizer-like names become sanitizers.",
        "",
    ]
    # Pysa does not allow import statements in model files.
    body: list[str] = []
    body.append("# Generated source models")
    if source_models:
        body.extend(source_models)
    else:
        body.append("# No suspicious source functions were found.")

    body.append("")
    body.append("# Generated sanitizer models")
    if sanitizer_models:
        body.extend(sanitizer_models)
    else:
        body.append("# No suspicious sanitizer functions were found.")

    body.append("")
    body.append("# Generated global source models")
    if global_models:
        body.extend(global_models)
    else:
        body.append("# No suspicious global sources were found.")

    body.append("")
    body.append("# Generated mapping access models")
    if mapping_models:
        body.extend(mapping_models)
    else:
        body.append("# No sensitive mapping accesses were found.")

    output_path.write_text("\n".join(header + body) + "\n")


def _is_model_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if stripped.startswith("def "):
        return True
    if ":" in stripped:
        before, _ = stripped.split(":", 1)
        return " " not in before and "(" not in before
    return False


def merge_models(
    base_models_path: Path = BASE_MODELS_PATH,
    generated_models_path: Path = GENERATED_MODELS_PATH,
    merged_models_path: Path = MERGED_MODELS_PATH,
) -> int:
    if not base_models_path.exists():
        raise FileNotFoundError(f"Base models file not found: {base_models_path}")

    base_content = base_models_path.read_text()
    generated_content = generated_models_path.read_text() if generated_models_path.exists() else ""

    base_lines = base_content.splitlines()
    generated_lines = generated_content.splitlines()

    base_model_lines = [line for line in base_lines if _is_model_line(line)]
    generated_model_lines = [line for line in generated_lines if _is_model_line(line)]

    combined_model_lines: list[str] = []
    seen: set[str] = set()

    for line in [*base_model_lines, *generated_model_lines]:
        normalized = line.strip()
        if normalized not in seen:
            combined_model_lines.append(normalized)
            seen.add(normalized)

    merged_lines = [
        "# Auto-generated by generate_models.py. Do not edit manually.",
        f"# Base models: {base_models_path}",
        f"# Generated models: {generated_models_path}",
        "",
    ]
    merged_lines.extend(combined_model_lines)

    merged_models_path.parent.mkdir(parents=True, exist_ok=True)
    merged_models_path.write_text("\n".join(merged_lines) + "\n")
    return len(combined_model_lines)


def main(scan_roots_override: Iterable[Path] | None = None) -> None:
    roots = scan_roots_override or SCAN_ROOTS
    source_models, sanitizer_models, global_models, mapping_models = scan_roots(roots)
    write_generated_models(source_models, sanitizer_models, global_models, mapping_models)
    merged_count = merge_models()

    print(
        "Wrote "
        f"{len(source_models)} source model(s), "
        f"{len(sanitizer_models)} sanitizer model(s), "
        f"{len(global_models)} global source model(s), "
        f"and {len(mapping_models)} mapping access model(s) "
        f"to {GENERATED_MODELS_PATH}"
    )
    print(f"Merged base + generated models into {MERGED_MODELS_PATH} ({merged_count} total model(s))")


if __name__ == "__main__":
    main()
