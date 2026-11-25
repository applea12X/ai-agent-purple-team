"""HTML that escapes by default.

The review UI renders what the corpus deliberately contains -- hostile HTML, Markdown, and
injection strings -- so the only way to put text on a page is through :func:`el`, which escapes
every child that is not already :class:`Markup` and every attribute value. ``Markup`` is produced
only by this module, from fixed tag and attribute names, so an evidence string can never become
markup by being passed through a template.

Two allowlists make the rule checkable rather than conventional: :data:`TAGS` and
:data:`ATTRIBUTES`. A tag or attribute outside them raises at render time, so a page cannot
emit ``<script>``, an ``on*`` handler, or a ``style`` attribute even by programmer error. Link
targets are built by :func:`path` from fixed segments and integer indexes, never from bundle
content, and must be same-origin absolute paths.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from urllib.parse import quote

#: Every tag the review UI emits. ``script``, ``style``, ``iframe``, ``object``, ``embed``,
#: ``img``, ``svg``, ``base`` and ``meta http-equiv`` are deliberately absent.
TAGS = frozenset(
    {
        "html",
        "head",
        "meta",
        "title",
        "link",
        "body",
        "header",
        "main",
        "nav",
        "footer",
        "section",
        "div",
        "span",
        "h1",
        "h2",
        "h3",
        "p",
        "a",
        "strong",
        "em",
        "small",
        "code",
        "pre",
        "ul",
        "li",
        "table",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "form",
        "fieldset",
        "legend",
        "label",
        "input",
        "textarea",
        "button",
        "br",
    }
)

#: Every attribute the review UI emits. No ``on*`` handler, no ``style``, no ``src``.
ATTRIBUTES = frozenset(
    {
        "lang",
        "charset",
        "name",
        "content",
        "rel",
        "href",
        "class",
        "action",
        "method",
        "type",
        "value",
        "checked",
        "required",
        "rows",
        "for",
        "id",
    }
)

#: Attributes whose value is a URL; each must be a same-origin absolute path built by ``path``.
URL_ATTRIBUTES = frozenset({"href", "action"})

VOID = frozenset({"meta", "link", "input", "br"})


class Markup(str):
    """A fragment this module built. Only :func:`el`, :func:`join` and :func:`page` make one."""

    __slots__ = ()


def text(value: object) -> Markup:
    """Escape any value for an HTML text or attribute context."""
    if isinstance(value, Markup):
        return value
    return Markup(html.escape(str(value), quote=True))


def join(parts: Iterable[object]) -> Markup:
    return Markup("".join(text(part) for part in parts if part is not None))


def path(*segments: object) -> str:
    """A same-origin absolute path from fixed segments; each segment is percent-encoded."""
    return "/" + "/".join(quote(str(segment), safe="") for segment in segments)


def el(tag: str, *children: object, **attributes: object) -> Markup:
    """Render one element. Children and attribute values are escaped unless already Markup.

    Attribute names are given as keywords; a trailing underscore is stripped (``class_``,
    ``for_``). ``True`` renders a bare boolean attribute; ``None`` and ``False`` omit it.
    """
    if tag not in TAGS:
        raise ValueError(f"tag not allowed in the review UI: {tag}")
    rendered: list[str] = []
    for raw_name, value in attributes.items():
        name = raw_name.rstrip("_").replace("_", "-")
        if name not in ATTRIBUTES:
            raise ValueError(f"attribute not allowed in the review UI: {name}")
        if value is None or value is False:
            continue
        if value is True:
            rendered.append(f" {name}")
            continue
        if name in URL_ATTRIBUTES and (
            not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
        ):
            raise ValueError("links in the review UI must be same-origin absolute paths")
        rendered.append(f' {name}="{html.escape(str(value), quote=True)}"')
    opening = f"<{tag}{''.join(rendered)}>"
    if tag in VOID:
        if children:
            raise ValueError(f"<{tag}> takes no children")
        return Markup(opening)
    body = "".join(_child(child) for child in children)
    return Markup(f"{opening}{body}</{tag}>")


def _child(child: object) -> str:
    if child is None:
        return ""
    if isinstance(child, Markup):
        return child
    if isinstance(child, (list, tuple)):
        return "".join(_child(item) for item in child)
    return text(child)


def page(title: str, *body: object) -> Markup:
    """A complete document: no inline style, no script, one same-origin stylesheet."""
    head = el(
        "head",
        el("meta", charset="utf-8"),
        el("meta", name="viewport", content="width=device-width, initial-scale=1"),
        el("title", title),
        el("link", rel="stylesheet", href=path("static", "review.css")),
    )
    return Markup("<!doctype html>" + el("html", head, el("body", *body), lang="en"))


STYLESHEET = """\
:root{--bg:#faf8ff;--fg:#211a32;--panel:#fff;--line:#ddd;--accent:#6531a0;--warn:#7a5c00;
--warnbg:#fff8e6;--bad:#8b1a1a;--badbg:#fdecec}
@media (prefers-color-scheme:dark){:root{--bg:#16121f;--fg:#ece8f5;--panel:#211b2e;
--line:#3a3150;--accent:#c7a6ff;--warn:#f0c766;--warnbg:#2e2714;--bad:#ff9a9a;--badbg:#3a1a1a}}
body{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;
background:var(--bg);color:var(--fg)}
a{color:var(--accent)}
section,.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:16px 20px;margin:16px 0}
.blinded{background:var(--warnbg);border:1px dashed var(--warn);border-radius:8px;padding:10px 14px}
.unverified{background:var(--badbg);border:1px solid var(--bad);color:var(--bad);border-radius:8px;
padding:10px 14px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;margin:0}
code{overflow-wrap:anywhere}
textarea{width:100%;font:inherit}
fieldset{border:1px solid var(--line);border-radius:8px;margin:12px 0}
"""
