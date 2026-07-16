"""Language adapters: map tree-sitter node shapes to a small neutral vocabulary.

The taint analyzer is written once against this interface; each language provides
an adapter that knows its grammar's node types and field names. This is what keeps
the analysis language-agnostic.

Maturity is tracked honestly in ``ADAPTERS``: Python and JavaScript/TypeScript are
implemented and tested; Go and Java parse (see ``substrate.treesitter``) but do not
yet have taint adapters, so they are absent here rather than half-working.
"""

from __future__ import annotations

import abc
from typing import Any

from crucible.substrate.treesitter import node_text


class LanguageAdapter(abc.ABC):
    language: str
    #: tree-sitter node types that introduce a new variable scope with a body.
    function_types: tuple[str, ...] = ()
    #: node types that represent property/index access (possible sources that are
    #: not calls, e.g. ``req.query.id`` or ``request.args["id"]``).
    access_types: tuple[str, ...] = ()

    @abc.abstractmethod
    def function_body(self, node: Any) -> Any | None:
        """Return the statement-container child of a function node, or None."""

    @abc.abstractmethod
    def param_names(self, func_node: Any) -> list[str]:
        ...

    @abc.abstractmethod
    def as_assignment(self, node: Any) -> tuple[Any, Any] | None:
        """If ``node`` is an assignment, return (target_node, value_node).

        The target node may be a plain identifier (a variable binding) or a
        property/index expression (a possible assignment sink, e.g. ``el.innerHTML``).
        """

    @abc.abstractmethod
    def as_call(self, node: Any) -> tuple[str, list[Any]] | None:
        """If ``node`` is a call, return (callee_text, [arg_nodes])."""

    @abc.abstractmethod
    def identifier_name(self, node: Any) -> str | None:
        ...

    @abc.abstractmethod
    def is_string_literal(self, node: Any) -> bool:
        ...

    def is_function(self, node: Any) -> bool:
        return node.type in self.function_types


def _field(node: Any, name: str) -> Any | None:
    return node.child_by_field_name(name)


class PythonAdapter(LanguageAdapter):
    language = "python"
    function_types = ("function_definition",)
    access_types = ("attribute", "subscript")
    _string_types = frozenset({"string", "concatenated_string"})

    def function_body(self, node: Any) -> Any | None:
        return _field(node, "body")

    def param_names(self, func_node: Any) -> list[str]:
        params = _field(func_node, "parameters")
        if params is None:
            return []
        names: list[str] = []
        for child in params.children:
            if child.type == "identifier":
                names.append(node_text(child))
            elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                ident = child.child_by_field_name("name") or next(
                    (c for c in child.children if c.type == "identifier"), None
                )
                if ident is not None:
                    names.append(node_text(ident))
        return names

    def as_assignment(self, node: Any) -> tuple[Any, Any] | None:
        if node.type != "assignment":
            return None
        left = _field(node, "left")
        right = _field(node, "right")
        if left is None or right is None:
            return None
        return left, right

    def as_call(self, node: Any) -> tuple[str, list[Any]] | None:
        if node.type != "call":
            return None
        fn = _field(node, "function")
        args_node = _field(node, "arguments")
        callee = node_text(fn) if fn is not None else ""
        args = _arg_nodes(args_node)
        return callee, args

    def identifier_name(self, node: Any) -> str | None:
        return node_text(node) if node.type == "identifier" else None

    def is_string_literal(self, node: Any) -> bool:
        return node.type in self._string_types


class JavaScriptAdapter(LanguageAdapter):
    """Handles both JavaScript and TypeScript (shared call/assignment shapes)."""

    language = "javascript"
    function_types = (
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
    )
    access_types = ("member_expression", "subscript_expression")
    _string_types = frozenset({"string", "template_string"})

    def function_body(self, node: Any) -> Any | None:
        return _field(node, "body")

    def param_names(self, func_node: Any) -> list[str]:
        params = _field(func_node, "parameters")
        if params is None:
            return []
        return [
            node_text(c) for c in params.children if c.type == "identifier"
        ]

    def as_assignment(self, node: Any) -> tuple[Any, Any] | None:
        if node.type == "variable_declarator":
            name = _field(node, "name")
            value = _field(node, "value")
            if name is None or value is None:
                return None
            return name, value
        if node.type == "assignment_expression":
            left = _field(node, "left")
            right = _field(node, "right")
            if left is None or right is None:
                return None
            return left, right
        return None

    def as_call(self, node: Any) -> tuple[str, list[Any]] | None:
        if node.type != "call_expression":
            return None
        fn = _field(node, "function")
        args_node = _field(node, "arguments")
        callee = node_text(fn) if fn is not None else ""
        args = _arg_nodes(args_node)
        return callee, args

    def identifier_name(self, node: Any) -> str | None:
        return node_text(node) if node.type == "identifier" else None

    def is_string_literal(self, node: Any) -> bool:
        return node.type in self._string_types


def _arg_nodes(args_node: Any) -> list[Any]:
    """Return real argument expression nodes, dropping punctuation."""
    if args_node is None:
        return []
    drop = {"(", ")", ",", "[", "]"}
    return [c for c in args_node.children if c.type not in drop and c.is_named]


ADAPTERS: dict[str, LanguageAdapter] = {
    "python": PythonAdapter(),
    "javascript": JavaScriptAdapter(),
    "typescript": JavaScriptAdapter(),
}


def adapter_for(language: str) -> LanguageAdapter | None:
    return ADAPTERS.get(language)
