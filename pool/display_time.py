"""Presentation-only time conversion; ledger timestamps always remain UTC."""

from datetime import datetime, timedelta, timezone
from html import escape


# Windows installations do not necessarily ship the IANA time-zone database.
# Hong Kong has a fixed UTC+8 offset for the supported service dates.
HONG_KONG = timezone(timedelta(hours=8), name="Asia/Hong_Kong")


def as_utc(value):
    if value is None or value == "":
        return None
    try:
        result = (datetime.fromtimestamp(value, timezone.utc) if isinstance(value, (int, float))
                  else datetime.fromisoformat(str(value).replace("Z", "+00:00")))
        return (result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc))
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def local_text(value, compact=False):
    stamp = as_utc(value)
    if stamp is None:
        return "—"
    return stamp.astimezone(HONG_KONG).strftime("%m-%d %H:%M" if compact else "%Y-%m-%d %H:%M") + " UTC+8"


def time_html(value, compact=False):
    stamp = as_utc(value)
    if stamp is None:
        return "—"
    original = stamp.isoformat(timespec="seconds").replace("+00:00", "Z")
    utc_title = stamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    return f'<time datetime="{escape(original, quote=True)}" title="{utc_title}">{local_text(value, compact)}</time>'
