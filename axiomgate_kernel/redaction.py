"""AxiomGate Kernel — Zero-Leak Secret Redactor (DLP Engine)

Deterministic credential masking preventing raw API keys, passwords, or tokens
from ever persisting or displaying in reports, SQLite, or UI.
"""
import logging
import re
import traceback
from typing import List, Tuple


# Pattern list: (name, compiled_regex)
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("OPENAI", re.compile(r"sk-[a-zA-Z0-9_-]{20,}")),
    ("ANTHROPIC", re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")),
    ("GITHUB_PAT", re.compile(r"github_pat_[a-zA-Z0-9_]{50,}")),
    ("GITHUB_TOKEN", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GOOGLE_AI", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("HUGGINGFACE", re.compile(r"hf_[a-zA-Z0-9]{34,}")),
    # sk_live_ has an underscore and therefore does NOT match the OPENAI
    # pattern above. AxiomGate itself bills through Stripe; a hardcoded live
    # key was the last format that should be allowed to slip past CRED-001
    # undetected.
    ("STRIPE_SECRET", re.compile(r"sk_(live|test)_[a-zA-Z0-9]{20,}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[a-zA-Z0-9]{10,}(-[a-zA-Z0-9]+)*")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----")),
    ("GENERIC_PASSWORD", re.compile(r"""password\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)),
    ("GENERIC_API_KEY", re.compile(r"""api_key\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)),
    ("GENERIC_SECRET", re.compile(r"""secret\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)),
    ("GENERIC_TOKEN", re.compile(r"""token\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)),
]


def _mask_match(category: str, matched_text: str) -> str:
    """Replace match with [REDACTED_SECRET:category-***last2]."""
    last2 = matched_text[-2:] if len(matched_text) >= 2 else "??"
    return f"[REDACTED_SECRET:{category.lower()}-***{last2}]"


def redact_secrets(text: str) -> str:
    """Redact all detected secrets in a text string.

    Returns the sanitized text with secrets replaced by category-tagged masks.
    """
    if not text:
        return text
    result = text
    for category, pattern in _PATTERNS:
        result = pattern.sub(lambda m: _mask_match(category, m.group()), result)
    return result


def scan_for_secrets(text: str) -> List[dict]:
    """Scan text for secret patterns and return a list of findings.

    Each finding: {category, span_start, span_end, redacted}
    """
    findings = []
    if not text:
        return findings
    for category, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "category": category,
                "span_start": match.start(),
                "span_end": match.end(),
                "redacted": _mask_match(category, match.group()),
                "original_length": len(match.group()),
            })
    return findings


def credential_pattern_count() -> int:
    """How many credential formats the DLP actually recognizes.

    The ZERO-LEAK badge in the PDF names this figure for the customer. It is
    fetched from here rather than written by hand, so that a badge can never
    claim more formats than _PATTERNS actually contains.
    """
    return len(_PATTERNS)


# Field names whose VALUE is always masked, regardless of what the value
# looks like. The format matching above asks "does the value look like a
# key?". That question has no answer for a free-form password like
# "hunter2". The name is then the only signal there is, and in an
# append-only HMAC-chained log a leak cannot be cleaned up after the fact --
# editing the entry breaks the chain that is the evidence. Hence fail-closed:
# better to mask a harmless field than to permanently archive a secret.
# Substring matching against the normalized name, so that "db_secret",
# "authToken", and "X-Api-Key" are all caught.
_SENSITIVE_KEY_PARTS: Tuple[str, ...] = (
    "password", "passwd", "secret", "token", "apikey", "authorization",
    "credential", "privatekey", "passphrase", "sessionkey", "accesskey",
)

_KEY_NORMALISE = re.compile(r"[^a-z0-9]")


def _is_sensitive_key(key: object) -> bool:
    """True if the field name itself marks the value as a secret."""
    if not isinstance(key, str):
        return False
    normalised = _KEY_NORMALISE.sub("", key.lower())
    return any(part in normalised for part in _SENSITIVE_KEY_PARTS)


def redact_dict(d):
    """Recursively redact secrets in every string — dict keys included.

    The keys are not decoration: authority_graph.nodes has the agent id as
    its key, and an agent id is built from the file's path. A key that was
    just copied straight through carried the secret into report.json. Tuples
    are included so that SQL parameters can be redacted at a single point in
    ScanStore.

    Two independent rules apply: the value's FORMAT (_PATTERNS) and the
    field's NAME (_SENSITIVE_KEY_PARTS). The name rule masks the entire value
    without looking at it, even when the value is not a string -- an integer
    or a list under "api_key" is just as much a secret as a string is.
    """
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            if _is_sensitive_key(k):
                out[redact_dict(k)] = "[REDACTED_SECRET:field-name]"
            else:
                out[redact_dict(k)] = redact_dict(v)
        return out
    if isinstance(d, list):
        return [redact_dict(item) for item in d]
    if isinstance(d, tuple):
        return tuple(redact_dict(item) for item in d)
    if isinstance(d, str):
        return redact_secrets(d)
    return d


class _RedactingFilter(logging.Filter):
    """Redacts every log record before it reaches a handler.

    The filter sits on the logger, not at the call site: a logger.error with
    an exception in it is the same class of bug as a print to stderr, and it
    is fixed at the same place -- the exit point. Without a configured
    handler, Python's lastResort writes the record straight to stderr, so an
    unredacted record is a leak even in a process that never sets up logging.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_secrets(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redact_arg(v)
                               for k, v in record.args.items()}
            else:
                record.args = tuple(_redact_arg(a) for a in record.args)
        # The traceback does not live in msg but in exc_info, and Formatter
        # only renders it after the filter has run. We render it ourselves
        # and cache the redacted result in exc_text -- Formatter reuses
        # exc_text once it is already set and then never touches the raw
        # text. Applies to both logger.exception() and
        # logger.error(..., exc_info=True).
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = "".join(
                    traceback.format_exception(*record.exc_info)).rstrip("\n")
        if record.exc_text:
            record.exc_text = redact_secrets(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_secrets(record.stack_info)
        return True


def _redact_arg(a: object) -> object:
    """Numbers are left as they are -- "%d" % "5" raises TypeError.

    A number cannot carry a key, and str()-ing it would break every %d and
    %f placeholder in a line that was never a leak.
    """
    if isinstance(a, bool) or not isinstance(a, (int, float, complex)):
        return redact_secrets(str(a))
    return a


def get_redacting_logger(name: str) -> logging.Logger:
    """The logger for name, with redaction attached exactly once.

    A single source of truth for what is allowed to leave the process via
    logging -- never use logging.getLogger directly in src/.
    """
    lg = logging.getLogger(name)
    if not any(isinstance(f, _RedactingFilter) for f in lg.filters):
        lg.addFilter(_RedactingFilter())
    return lg
