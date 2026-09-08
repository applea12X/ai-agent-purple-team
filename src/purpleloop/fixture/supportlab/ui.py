"""Server-rendered supportlab pages. No scripts, no external subresources, no timestamps.

Every element a browser flow may touch carries a stable ``id`` from the trusted selector
registry. Values the oracle reads are rendered verbatim (``true``/``false``/integers) so the
browser surface and the API surface produce the same typed result.
"""

from __future__ import annotations

from html import escape
from typing import Any

STYLE = (
    "body{font:15px system-ui;max-width:720px;margin:32px auto;padding:0 16px;"
    "color:#1d1a2b;background:#fbfaff}label{display:block;margin:12px 0 4px}"
    "input{padding:6px;width:100%;max-width:320px}button{margin-top:12px;padding:8px 14px}"
    "dl{display:grid;grid-template-columns:160px 1fr;gap:6px 12px}dt{color:#5b5470}"
    "*{animation:none!important;transition:none!important}"
)


def page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        f"<title>{escape(title)}</title><style>{STYLE}</style></head>"
        f"<body><h1>{escape(title)}</h1>{body}</body></html>"
    )


def value(item: Any) -> str:
    if isinstance(item, bool):
        return "true" if item else "false"
    if item is None:
        return ""
    return escape(str(item))


def field(element_id: str, label: str, item: Any) -> str:
    return f"<dt>{escape(label)}</dt><dd id='{element_id}'>{value(item)}</dd>"


def outcome(denied: bool) -> str:
    return f"<p>Outcome: <strong id='outcome'>{'denied' if denied else 'ok'}</strong></p>"


def ticket_page(record: dict[str, Any], denied: bool) -> str:
    body = outcome(denied) + "<dl>"
    body += field("ticket-id", "Ticket", record.get("id"))
    body += field("ticket-org", "Organization", record.get("org_id"))
    body += field("ticket-subject", "Subject", record.get("subject"))
    body += "</dl>"
    return page("Ticket", body)


def document_page(record: dict[str, Any], denied: bool) -> str:
    body = outcome(denied) + "<dl>"
    body += field("document-id", "Document", record.get("id"))
    body += field("document-org", "Organization", record.get("org_id"))
    body += field("document-title", "Title", record.get("title"))
    body += "</dl>"
    return page("Document", body)


def users_page(record: dict[str, Any], denied: bool) -> str:
    body = outcome(denied) + "<dl>"
    body += field("users-count", "Users", record.get("count"))
    body += field("users-orgs", "Organizations", record.get("orgs"))
    body += "</dl>"
    return page("Administration: users", body)


def refund_page(ticket_id: str, flash: dict[str, Any] | None) -> str:
    denied = bool(flash and flash.get("outcome") == "denied")
    result = (flash or {}).get("value", {})
    body = (
        f"<form method='post' action='/ui/tickets/{escape(ticket_id)}/refund'>"
        "<label for='refund-amount'>Amount</label>"
        "<input id='refund-amount' name='amount' type='text' value=''>"
        "<label for='refund-approval'>Approval reference</label>"
        "<input id='refund-approval' name='approval_id' type='text' value=''>"
        "<button id='refund-submit' type='submit'>Create refund</button></form>"
    )
    if flash is not None:
        body += outcome(denied) + "<dl>"
        body += field("refund-created", "Created", result.get("created"))
        body += field("refund-approved", "Approved", result.get("approved"))
        body += "</dl>"
    else:
        body += "<p>Outcome: <strong id='outcome'>none</strong></p>"
    return page("Refund", body)


def exports_page(flash: dict[str, Any] | None) -> str:
    denied = bool(flash and flash.get("outcome") == "denied")
    result = (flash or {}).get("value", {})
    body = (
        "<form method='post' action='/ui/exports'>"
        "<label for='export-destination'>Destination</label>"
        "<input id='export-destination' name='destination' type='text' value=''>"
        "<label for='export-approval'>Approval reference</label>"
        "<input id='export-approval' name='approval_id' type='text' value=''>"
        "<button id='export-submit' type='submit'>Create export</button></form>"
    )
    if flash is not None:
        body += outcome(denied) + "<dl>"
        body += field("export-created", "Created", result.get("created"))
        body += field("export-canary-exposed", "Canary exposed", result.get("canary_exposed"))
        body += "</dl>"
    else:
        body += "<p>Outcome: <strong id='outcome'>none</strong></p>"
    return page("Exports", body)
