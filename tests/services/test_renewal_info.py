"""Tests for ARI renewal info service (draft-ietf-acme-ari)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from acmeeh.config.settings import AriSettings
from acmeeh.services.renewal_info import RenewalInfoService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ari_settings(**kwargs) -> AriSettings:
    defaults = dict(enabled=True, renewal_percentage=0.6667, path="/ari")
    defaults.update(kwargs)
    return AriSettings(**defaults)


@dataclass(frozen=True)
class FakeCert:
    id: UUID
    serial_number: str
    not_before_cert: datetime
    not_after_cert: datetime
    revoked_at: datetime | None = None


class StubCertRepo:
    def __init__(self):
        self._by_serial: dict[str, FakeCert] = {}

    def add(self, cert: FakeCert):
        self._by_serial[cert.serial_number] = cert

    def find_by_serial(self, serial_hex: str) -> FakeCert | None:
        return self._by_serial.get(serial_hex)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cert_repo():
    return StubCertRepo()


@pytest.fixture
def settings():
    return _ari_settings()


@pytest.fixture
def service(cert_repo, settings):
    return RenewalInfoService(cert_repo, settings)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWindowComputation:
    """suggestedWindow.start = notAfter - (validity * renewal_pct)."""

    def test_window_start_computation(self, cert_repo):
        now = datetime.now(UTC)
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=60)
        validity_seconds = (not_after - not_before).total_seconds()  # 90 days

        cert = FakeCert(
            id=uuid4(),
            serial_number="abc123",
            not_before_cert=not_before,
            not_after_cert=not_after,
        )
        cert_repo.add(cert)

        pct = 0.6667
        settings = _ari_settings(renewal_percentage=pct)
        service = RenewalInfoService(cert_repo, settings)

        result = service.get_renewal_info("abc123")
        assert result is not None
        assert "suggestedWindow" in result

        window = result["suggestedWindow"]
        assert "start" in window
        assert "end" in window

        # Verify the end is notAfter
        window_end = datetime.fromisoformat(window["end"])
        assert abs((window_end - not_after).total_seconds()) < 2

        # Verify start = notAfter - (validity * pct)
        expected_offset = validity_seconds * pct
        expected_start = not_after - timedelta(seconds=expected_offset)
        window_start = datetime.fromisoformat(window["start"])
        assert abs((window_start - expected_start).total_seconds()) < 2

    def test_different_renewal_percentage(self, cert_repo):
        now = datetime.now(UTC)
        not_before = now - timedelta(days=45)
        not_after = now + timedelta(days=45)

        cert = FakeCert(
            id=uuid4(),
            serial_number="def456",
            not_before_cert=not_before,
            not_after_cert=not_after,
        )
        cert_repo.add(cert)

        # Use 50% renewal percentage
        settings = _ari_settings(renewal_percentage=0.5)
        service = RenewalInfoService(cert_repo, settings)

        result = service.get_renewal_info("def456")
        assert result is not None

        validity = (not_after - not_before).total_seconds()
        expected_start = not_after - timedelta(seconds=validity * 0.5)
        window_start = datetime.fromisoformat(result["suggestedWindow"]["start"])
        assert abs((window_start - expected_start).total_seconds()) < 2


class TestCertIDEncoding:
    """CertID encoding/decoding."""

    def test_direct_serial_lookup(self, cert_repo, service):
        cert = FakeCert(
            id=uuid4(),
            serial_number="1a2b3c",
            not_before_cert=datetime.now(UTC) - timedelta(days=10),
            not_after_cert=datetime.now(UTC) + timedelta(days=80),
        )
        cert_repo.add(cert)

        result = service.get_renewal_info("1a2b3c")
        assert result is not None

    def test_base64url_certid_lookup(self, cert_repo, service):
        cert = FakeCert(
            id=uuid4(),
            serial_number="deadbeef",
            not_before_cert=datetime.now(UTC) - timedelta(days=10),
            not_after_cert=datetime.now(UTC) + timedelta(days=80),
        )
        cert_repo.add(cert)

        # Encode as base64url: "AKI.deadbeef"
        cert_id_raw = "someAKI.deadbeef"
        cert_id_b64 = (
            base64.urlsafe_b64encode(cert_id_raw.encode("ascii")).rstrip(b"=").decode("ascii")
        )

        result = service.get_renewal_info(cert_id_b64)
        assert result is not None

    def test_invalid_certid_returns_none(self, service):
        # Non-existent serial
        result = service.get_renewal_info("nonexistent")
        assert result is None


def _rfc9773_cert_id(aki: bytes, serial: int) -> str:
    """certID as an ACME client builds it (RFC 9773 s4.1).

    ``base64url(AKI keyIdentifier) "." base64url(DER INTEGER value octets of the serial)``
    -- two separately encoded parts, no padding.  A serial whose high bit is set gets a
    leading 0x00 octet (two's complement), exactly as in the certificate.
    """
    octets = serial.to_bytes((serial.bit_length() + 7) // 8 or 1, "big")
    if octets[0] & 0x80:
        octets = b"\x00" + octets
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")  # noqa: E731
    return f"{b64(aki)}.{b64(octets)}"


class TestRfc9773CertID:
    """Real ACME clients (lego, certbot, ...) send the RFC 9773 form."""

    AKI = bytes.fromhex("34d6b9c0c0cff75cac870 e0c1b46dc7541a64a4a".replace(" ", ""))

    @pytest.mark.parametrize(
        ("serial", "stored"),
        [
            (0x0249, "249"),  # odd number of hex digits: stored without leading zero
            (0x248, "248"),
            (0xDEADBEEF, "deadbeef"),  # high bit set: DER adds a 0x00 octet
            (0x7F, "7f"),
            (0x80, "80"),
            ((1 << 159) - 12345, format((1 << 159) - 12345, "x")),  # 20-octet random-style serial
        ],
    )
    def test_serial_is_found(self, cert_repo, service, serial, stored):
        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number=stored,
                not_before_cert=datetime.now(UTC) - timedelta(days=10),
                not_after_cert=datetime.now(UTC) + timedelta(days=80),
            ),
        )
        result = service.get_renewal_info(_rfc9773_cert_id(self.AKI, serial))
        assert result is not None
        assert "suggestedWindow" in result

    def test_lego_vector(self, cert_repo, service):
        """The exact certID lego sent for serial 0x0249 against a test cluster."""
        cert_repo.add(
            FakeCert(
                id=uuid4(),
                serial_number="249",
                not_before_cert=datetime.now(UTC) - timedelta(days=1),
                not_after_cert=datetime.now(UTC) + timedelta(days=89),
            ),
        )
        assert service.get_renewal_info("NNa5wM_M91yshOMB8iKUGDbc8Vo.Akk") is not None

    def test_unknown_serial_returns_none(self, service):
        assert service.get_renewal_info(_rfc9773_cert_id(self.AKI, 0xFFFF)) is None

    @pytest.mark.parametrize("cert_id", ["abc.", ".abc", "a.b.c", "AKI.!!!not-base64!!!", "."])
    def test_malformed_returns_none_not_an_exception(self, service, cert_id):
        assert service.get_renewal_info(cert_id) is None


class TestRevokedCert:
    """Revoked cert -> window starts now."""

    def test_revoked_cert_window_starts_now(self, cert_repo, service):
        now = datetime.now(UTC)
        cert = FakeCert(
            id=uuid4(),
            serial_number="revoked01",
            not_before_cert=now - timedelta(days=60),
            not_after_cert=now + timedelta(days=30),
            revoked_at=now - timedelta(hours=1),
        )
        cert_repo.add(cert)

        result = service.get_renewal_info("revoked01")
        assert result is not None

        window_start = datetime.fromisoformat(result["suggestedWindow"]["start"])
        # Window start should be approximately "now" (within a few seconds)
        assert abs((window_start - now).total_seconds()) < 5


class TestCertNotFound:
    """Certificate not found -> returns None."""

    def test_unknown_serial_returns_none(self, service):
        result = service.get_renewal_info("does-not-exist")
        assert result is None

    def test_empty_string_returns_none(self, service):
        result = service.get_renewal_info("")
        assert result is None


class TestRetryAfter:
    """retryAfter field is included in response."""

    def test_retry_after_is_present(self, cert_repo, service):
        now = datetime.now(UTC)
        cert = FakeCert(
            id=uuid4(),
            serial_number="retry01",
            not_before_cert=now - timedelta(days=10),
            not_after_cert=now + timedelta(days=80),
        )
        cert_repo.add(cert)

        result = service.get_renewal_info("retry01")
        assert result is not None
        assert "retryAfter" in result
        assert isinstance(result["retryAfter"], int)
        assert result["retryAfter"] >= 3600  # Minimum 1 hour
