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
    # sk_live_ har understreck och matchar därför INTE OPENAI-mönstret ovan.
    # AxiomGate fakturerar självt via Stripe; en hårdkodad live-nyckel var det
    # sista formatet som borde gå oupptäckt förbi CRED-001.
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
    """Hur många kreditivformat DLP:n faktiskt känner igen.

    ZERO-LEAK-badgen i PDF:en namnger siffran för kunden. Den hämtas härifrån
    i stället för att skrivas för hand, så att en badge aldrig kan påstå fler
    format än _PATTERNS innehåller.
    """
    return len(_PATTERNS)


# Fältnamn vars VÄRDE alltid maskeras, oavsett hur värdet ser ut.
# Formatmatchningen ovan frågar "ser värdet ut som en nyckel?". Den frågan har
# inget svar för ett fritt lösenord som "hunter2". Namnet är då den enda
# signalen som finns, och i en append-only HMAC-kedjad logg kan en läcka inte
# städas bort i efterhand -- att redigera posten bryter kedjan som är beviset.
# Därför fail-closed: hellre maskera ett harmlöst fält än arkivera en hemlighet
# permanent. Substrängmatchning mot normaliserat namn, så att "db_secret",
# "authToken" och "X-Api-Key" alla fångas.
_SENSITIVE_KEY_PARTS: Tuple[str, ...] = (
    "password", "passwd", "secret", "token", "apikey", "authorization",
    "credential", "privatekey", "passphrase", "sessionkey", "accesskey",
)

_KEY_NORMALISE = re.compile(r"[^a-z0-9]")


def _is_sensitive_key(key: object) -> bool:
    """True om fältnamnet i sig utpekar värdet som en hemlighet."""
    if not isinstance(key, str):
        return False
    normalised = _KEY_NORMALISE.sub("", key.lower())
    return any(part in normalised for part in _SENSITIVE_KEY_PARTS)


def redact_dict(d):
    """Recursively redact secrets in every string — dict keys included.

    Nycklarna är inte dekoration: authority_graph.nodes har agent-id som nyckel,
    och ett agent-id byggs av filens sökväg. En nyckel som bara kopierades rakt
    igenom bar hemligheten in i report.json. Tupler tas med för att kunna
    redigera SQL-parametrar i en enda punkt i ScanStore.

    Två oberoende regler gäller: värdets FORMAT (_PATTERNS) och fältets NAMN
    (_SENSITIVE_KEY_PARTS). Namnregeln maskerar hela värdet utan att titta på
    det, även när värdet inte är en sträng -- ett heltal eller en lista under
    "api_key" är lika mycket en hemlighet som en sträng är.
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
    """Redigerar varje loggpost innan den når en handler.

    Filtret sitter på loggaren, inte på anropsplatsen: en logger.error med
    ett undantag i sig är samma felklass som en print till stderr, och den
    fixas på samma ställe -- utgången. Utan konfigurerad handler skriver
    Pythons lastResort posten rakt till stderr, så en oredigerad post är
    en läcka även i en process som aldrig sätter upp loggning.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_secrets(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redigera_arg(v)
                               for k, v in record.args.items()}
            else:
                record.args = tuple(_redigera_arg(a) for a in record.args)
        # Tracebacken ligger inte i msg utan i exc_info, och Formatter renderar
        # den forst efter att filtret kort. Vi renderar den sjalva och cachar
        # det redigerade resultatet i exc_text -- Formatter aterandvander
        # exc_text nar det redan ar satt och ror da aldrig den raa texten.
        # Galler bade logger.exception() och logger.error(..., exc_info=True).
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = "".join(
                    traceback.format_exception(*record.exc_info)).rstrip("\n")
        if record.exc_text:
            record.exc_text = redact_secrets(record.exc_text)
        if record.stack_info:
            record.stack_info = redact_secrets(record.stack_info)
        return True


def _redigera_arg(a: object) -> object:
    """Tal lämnas som de är -- "%d" % "5" kastar TypeError.

    Ett tal kan inte bära en nyckel, och att str():a det skulle fälla varje
    %d- och %f-placeholder i en rad som aldrig var en läcka.
    """
    if isinstance(a, bool) or not isinstance(a, (int, float, complex)):
        return redact_secrets(str(a))
    return a


def get_redacting_logger(name: str) -> logging.Logger:
    """Loggaren för name, med redigeringen påsatt en gång.

    En sanningskälla för vad som får lämna processen via logging -- använd
    aldrig logging.getLogger direkt i src/.
    """
    lg = logging.getLogger(name)
    if not any(isinstance(f, _RedactingFilter) for f in lg.filters):
        lg.addFilter(_RedactingFilter())
    return lg
