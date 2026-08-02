"""Tests for the firebase-messaging reconnect-storm logging guard (#285).

The guard defuses the CPU bomb described in #285: firebase-messaging's
listen loop logging a full, ever-growing traceback on every iteration while
its stream reader is poisoned. Stripping `exc_info` in a logging.Filter
(which runs before handlers format the record) keeps the one-line message
but skips the quadratic traceback formatting on Python 3.14.
"""

from __future__ import annotations

import binascii
import logging
import sys
from base64 import urlsafe_b64decode
from typing import TYPE_CHECKING

import pytest

from custom_components.aegis_ajax.notification_fcm_guard import (
    _DECRYPT_GUARD_FLAG,
    _PRISTINE_DECRYPT_ATTR,
    FCM_PUSH_LOGGER_NAME,
    GUARD_LOGGER_NAME,
    FcmExceptionLogThrottle,
    _pad_urlsafe_b64,
    attach_fcm_log_guard,
    install_fcm_decrypt_guard,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


def _make_record(
    *, with_exc: bool = True, msg: str = "Unexpected exception during read\n"
) -> logging.LogRecord:
    exc_info = None
    if with_exc:
        try:
            raise ConnectionResetError("Connection lost")
        except ConnectionResetError:
            exc_info = sys.exc_info()
    return logging.LogRecord(
        name=FCM_PUSH_LOGGER_NAME,
        level=logging.ERROR,
        pathname="fcmpushclient.py",
        lineno=717,
        msg=msg,
        args=(),
        exc_info=exc_info,
    )


class TestFcmExceptionLogThrottle:
    def test_under_threshold_keeps_exc_info(self) -> None:
        throttle = FcmExceptionLogThrottle(max_exceptions=3, window_seconds=60, clock=lambda: 0.0)
        for _ in range(3):
            record = _make_record()
            assert throttle.filter(record) is True
            assert record.exc_info is not None

    def test_over_threshold_strips_exc_info_but_keeps_record(self) -> None:
        throttle = FcmExceptionLogThrottle(max_exceptions=3, window_seconds=60, clock=lambda: 0.0)
        for _ in range(3):
            throttle.filter(_make_record())

        record = _make_record()
        # The record must still be emitted (returns True) — only the
        # traceback is dropped, so operators keep a one-line trace.
        assert throttle.filter(record) is True
        assert record.exc_info is None
        assert record.exc_text is None
        assert record.stack_info is None
        assert "traceback suppressed" in record.msg

    def test_window_expiry_restores_exc_info(self) -> None:
        now = {"t": 0.0}
        throttle = FcmExceptionLogThrottle(
            max_exceptions=2, window_seconds=60, clock=lambda: now["t"]
        )
        throttle.filter(_make_record())
        throttle.filter(_make_record())
        suppressed = _make_record()
        throttle.filter(suppressed)
        assert suppressed.exc_info is None

        now["t"] = 61.0
        record = _make_record()
        assert throttle.filter(record) is True
        assert record.exc_info is not None

    def test_records_without_exc_info_pass_untouched_and_uncounted(self) -> None:
        throttle = FcmExceptionLogThrottle(max_exceptions=1, window_seconds=60, clock=lambda: 0.0)
        for _ in range(5):
            record = _make_record(with_exc=False)
            assert throttle.filter(record) is True
            assert "traceback suppressed" not in record.msg
        # The plain records above must not have consumed the budget.
        record = _make_record()
        assert throttle.filter(record) is True
        assert record.exc_info is not None


class TestEndToEndSuppression:
    def test_handler_never_formats_traceback_past_threshold(self) -> None:
        """Storm simulation through the real logging pipeline.

        Emulates fcmpushclient's `_logger.exception(...)` per-iteration storm
        and asserts the handler (where traceback formatting — the actual CPU
        cost — happens) only ever formats the allowed number of tracebacks.
        """
        import io

        logger = logging.getLogger(FCM_PUSH_LOGGER_NAME)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        original_filters = list(logger.filters)
        original_propagate = logger.propagate
        logger.addHandler(handler)
        logger.propagate = False
        try:
            attach_fcm_log_guard()
            for _ in range(20):
                try:
                    raise ConnectionResetError("Connection lost")
                except ConnectionResetError:
                    logger.exception("Unexpected exception during read\n")
            output = stream.getvalue()
            assert output.count("Traceback") == 5
            assert output.count("traceback suppressed") == 15
        finally:
            logger.removeHandler(handler)
            logger.propagate = original_propagate
            for f in list(logger.filters):
                if f not in original_filters:
                    logger.removeFilter(f)


class TestAttachFcmLogGuard:
    def test_attach_is_idempotent(self) -> None:
        logger = logging.getLogger(FCM_PUSH_LOGGER_NAME)
        original_filters = list(logger.filters)
        try:
            attach_fcm_log_guard()
            attach_fcm_log_guard()
            guards = [f for f in logger.filters if isinstance(f, FcmExceptionLogThrottle)]
            assert len(guards) == 1
        finally:
            for f in list(logger.filters):
                if f not in original_filters:
                    logger.removeFilter(f)


class TestPadUrlsafeB64:
    """`_pad_urlsafe_b64` is the root-cause fix for #373.

    `crypto-key` / `encryption` header values are URL-safe base64 that may
    legitimately arrive without trailing `=`. The library pads the two stored
    key values it decodes but not these two, so an unpadded header raises
    `binascii.Error` — which is a `ValueError`, so the listen loop's
    `except (OSError, EOFError)` misses it and the client shuts down.
    """

    def test_pads_length_two_remainder(self) -> None:
        assert urlsafe_b64decode(_pad_urlsafe_b64("YWJjZA")) == b"abcd"

    def test_pads_length_three_remainder(self) -> None:
        assert urlsafe_b64decode(_pad_urlsafe_b64("YWJjZGU")) == b"abcde"

    def test_already_padded_is_unchanged_in_value(self) -> None:
        assert urlsafe_b64decode(_pad_urlsafe_b64("YWJj")) == b"abc"

    def test_explicit_padding_survives(self) -> None:
        assert urlsafe_b64decode(_pad_urlsafe_b64("YWJjZA==")) == b"abcd"

    def test_unpadded_input_raises_without_the_fix(self) -> None:
        """Pins the bug itself, so the test fails if the premise changes."""
        with pytest.raises(binascii.Error):
            urlsafe_b64decode("YWJjZGU")


def _make_fake_client(decrypt=None):  # noqa: ANN001, ANN202
    """Build a fresh stand-in for `FcmPushClient` per test.

    A factory rather than a shared class: `install_fcm_decrypt_guard` mutates
    the class it is handed, so reusing one would leak the patch between tests.
    """
    calls: list[tuple[str, str]] = []

    def _default(
        credentials: dict[str, object],
        crypto_key_str: str,
        salt_str: str,
        raw_data: bytes,
    ) -> bytes:
        calls.append((crypto_key_str, salt_str))
        # Mirrors the library: these two are decoded without padding.
        urlsafe_b64decode(crypto_key_str.encode("ascii"))
        urlsafe_b64decode(salt_str.encode("ascii"))
        return b"decrypted"

    class _FakeClient:
        _decrypt_raw_data = staticmethod(decrypt or _default)

    _FakeClient.calls = calls  # type: ignore[attr-defined]
    return _FakeClient


def _explode(*_args: object) -> bytes:
    raise ValueError("not recoverable")


class TestFcmDecryptGuard:
    def test_unpadded_values_now_decrypt(self) -> None:
        client = _make_fake_client()
        install_fcm_decrypt_guard(client)
        assert client._decrypt_raw_data({}, "YWJjZGU", "YWJjZA", b"") == b"decrypted"

    def test_padded_values_still_decrypt(self) -> None:
        client = _make_fake_client()
        install_fcm_decrypt_guard(client)
        assert client._decrypt_raw_data({}, "YWJj", "YWJj", b"") == b"decrypted"

    def test_undecodable_frame_returns_empty_instead_of_raising(self) -> None:
        """The whole point: the listen loop must reach its acknowledgement.

        A frame we genuinely cannot decrypt must not propagate, because the
        exception would escape `_handle_data_message` before the library acks
        the message — leaving it unacked and redelivered forever (#373).
        """
        client = _make_fake_client(_explode)
        install_fcm_decrypt_guard(client)
        assert client._decrypt_raw_data({}, "YWJj", "YWJj", b"") == b""

    def test_non_base64_garbage_is_swallowed(self) -> None:
        client = _make_fake_client()
        install_fcm_decrypt_guard(client)
        assert client._decrypt_raw_data({}, "!!!not base64!!!", "YWJj", b"") == b""

    def test_install_is_idempotent(self) -> None:
        client = _make_fake_client()
        install_fcm_decrypt_guard(client)
        first = client._decrypt_raw_data
        install_fcm_decrypt_guard(client)
        assert client._decrypt_raw_data is first

    def test_failure_logs_a_warning_once_then_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """Symptom is invisible at HA's default level, so the first one is a
        WARNING; repeats drop to DEBUG so a persistent sender can't spam."""
        client = _make_fake_client(_explode)
        install_fcm_decrypt_guard(client)
        with caplog.at_level(logging.DEBUG, logger=GUARD_LOGGER_NAME):
            for _ in range(3):
                client._decrypt_raw_data({}, "YWJj", "YWJj", b"")
        records = [r for r in caplog.records if r.name == GUARD_LOGGER_NAME]
        assert [r.levelno for r in records] == [
            logging.WARNING,
            logging.DEBUG,
            logging.DEBUG,
        ]

    def test_original_receives_padded_values(self) -> None:
        client = _make_fake_client()
        install_fcm_decrypt_guard(client)
        client._decrypt_raw_data({}, "YWJjZGU", "YWJjZA", b"")
        crypto_key, salt = client.calls[-1]
        assert crypto_key.endswith("=")
        assert salt.endswith("=")


class TestFcmDecryptGuardAgainstRealLibrary:
    """Characterisation against the real `FcmPushClient`.

    A hand-rolled double can't prove the patch lands on the code path that
    actually crashed, so this pins the real class: unpadded input raises
    before the guard and is contained after it.
    """

    @pytest.fixture
    def unguarded_cls(self) -> Iterator[type]:
        """Yield the real class with the guard provably not installed.

        The guard patches the class itself, so any earlier test that started a
        push client leaves it installed process-wide. Snapshotting and undoing
        that here makes these tests independent of suite order — without it,
        `pristine` would capture the already-guarded function and the
        restore-check below would assert against our own patch.
        """
        pytest.importorskip("firebase_messaging")
        from firebase_messaging.fcmpushclient import FcmPushClient

        cls = FcmPushClient
        had_flag = getattr(cls, _DECRYPT_GUARD_FLAG, False)
        installed = cls.__dict__["_decrypt_raw_data"]
        if had_flag:
            # Reach past our own patch to the function the library shipped.
            cls._decrypt_raw_data = staticmethod(getattr(cls, _PRISTINE_DECRYPT_ATTR))
            delattr(cls, _DECRYPT_GUARD_FLAG)
        try:
            yield cls
        finally:
            cls._decrypt_raw_data = installed
            if had_flag:
                setattr(cls, _DECRYPT_GUARD_FLAG, True)
            elif getattr(cls, _DECRYPT_GUARD_FLAG, False):
                delattr(cls, _DECRYPT_GUARD_FLAG)

    def test_unpadded_input_raises_in_the_unpatched_library(self, unguarded_cls: type) -> None:
        """The premise of #373. Fails if upstream ever fixes it, which is the
        signal to drop our patch."""
        with pytest.raises(binascii.Error):
            unguarded_cls._decrypt_raw_data({}, "YWJjZGU", "YWJjZA", b"")

    def test_guard_contains_it_on_the_real_class(self, unguarded_cls: type) -> None:
        install_fcm_decrypt_guard(unguarded_cls)
        # Padding no longer raises; the crypto beyond it still fails on these
        # dummy values, and that failure is contained too.
        assert unguarded_cls._decrypt_raw_data({}, "YWJjZGU", "YWJjZA", b"") == b""
