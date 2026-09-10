"""parse_mandate — formatparsning av mandatsträngar.

Tre defekter i samma funktion, alla funna genom extern granskning 2026-09-09
och verifierade genom skarp körning.
"""

from datetime import datetime, timezone
import subprocess
import sys

import pytest

from axiomgate_kernel.principal_context import parse_mandate


class TestParseMandateTidsstampel:
    """split(':') styckar ISO-tidstämpeln som själv innehåller kolon.

    'execute:expires:2026-12-31T23:59:59Z' → parts[2] blir '2026-12-31T23'
    och expires_at landar på 23:00:00Z. 59 minuter 59 sekunder tappas tyst,
    och mandatet löper ut tidigare än det påstår.
    """

    def test_hel_isotidstampel_bevaras(self):
        m = parse_mandate("execute:expires:2026-12-31T23:59:59Z")
        assert m is not None
        assert m.expires_at == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_parent_hittas_efter_isotidstampel(self):
        """parts[3] == 'parent' stämmer aldrig när tidstämpeln ätit index 2-4.

        Härkomstkedjan bryts tyst: parent_mandate_id blir None utan felkod,
        så en delegerad behörighet ser ut som ett rotmandat.
        """
        m = parse_mandate("execute:expires:2026-12-31T23:59:59Z:parent:abc")
        assert m is not None
        assert m.parent_mandate_id == "abc"
        assert m.expires_at == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


class TestParseMandateOkantFormat:
    """Docstringens exempel 'execute:2026-12-31T23:59:59Z' saknar 'expires'.

    Grenen kräver parts[1] == 'expires', så tidstämpeln ignoreras helt och
    expires_at blir None medan is_valid är True. Ett mandat som ser
    tidsbegränsat ut löper aldrig ut — fail-open i mandatlagret.
    """

    def test_tidsstampel_utan_expires_avvisas(self):
        assert parse_mandate("execute:2026-12-31T23:59:59Z") is None

    def test_naket_scope_ar_fortfarande_giltigt(self):
        m = parse_mandate("execute")
        assert m is not None
        assert m.expires_at is None
        assert m.is_valid is True


class TestParseMandateIdStabilitet:
    """mandate_id byggs på hash(), som randomiseras per process (PYTHONHASHSEED).

    Samma mandatsträng får olika id i två processer, så ett id kan varken
    korsrefereras i audit-loggen eller matchas mot parent_mandate_id över
    ett processbyte.
    """

    def test_samma_strang_ger_samma_id_over_processer(self):
        kod = (
            "from axiomgate_kernel.principal_context import parse_mandate;"
            "print(parse_mandate('execute:expires:2026-12-31T23:59:59Z').mandate_id)"
        )
        ids = {
            subprocess.run([sys.executable, "-c", kod], capture_output=True,
                           text=True, check=True).stdout.strip()
            for _ in range(3)
        }
        assert len(ids) == 1, f"mandate_id varierar mellan processer: {ids}"
