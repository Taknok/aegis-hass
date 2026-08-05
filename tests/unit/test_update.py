"""Tests for the read-only update.py platform (hub firmware)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from custom_components.aegis_ajax.api.hub_object import (
    DEVICE_FW_STATE_COMPLETED,
    DEVICE_FW_STATE_DOWNLOADED,
    DEVICE_FW_STATE_DOWNLOADING,
    DEVICE_FW_STATE_FAILED,
    DEVICE_FW_STATE_INSTALLING,
    DEVICE_FW_STATE_NOT_STARTED,
    HUB_FW_STATE_DOWNLOADING,
    HUB_FW_STATE_NOT_STARTED,
    DeviceFirmwareUpdateInfo,
    HubFirmwareUpdateInfo,
)
from custom_components.aegis_ajax.update import AjaxDeviceFirmwareUpdate, AjaxHubFirmwareUpdate

if TYPE_CHECKING:
    from custom_components.aegis_ajax.api.models import Device


class TestAjaxHubFirmwareUpdate:
    @staticmethod
    def _make_coordinator(
        info: HubFirmwareUpdateInfo | None,
        hub_id: str = "002B1A51",
        firmware_version: str | None = None,
    ) -> MagicMock:
        from custom_components.aegis_ajax.api.models import Device
        from custom_components.aegis_ajax.const import DeviceState

        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.devices = {
            hub_id: Device(
                id=hub_id,
                hub_id=hub_id,
                name="Hub",
                device_type="hub",
                room_id=None,
                group_id=None,
                state=DeviceState.ONLINE,
                malfunctions=0,
                bypassed=False,
                statuses={},
                battery=None,
            )
        }
        coordinator.hub_firmware_updates = {hub_id: info} if info else {}
        # Must be a real dict, not the MagicMock default: `.get()` on a
        # MagicMock returns a truthy MagicMock, which would make every test
        # here look like the hub had reported a firmware version (#388).
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState

        coordinator.hub_network = (
            {hub_id: HubNetworkState(firmware_version=firmware_version)}
            if firmware_version is not None
            else {}
        )
        return coordinator

    def test_unique_id_namespaced_by_hub(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity._attr_unique_id == "aegis_ajax_002B1A51_firmware"

    def test_installed_version_is_constant_placeholder(self) -> None:
        """Hub has not reported its version over HTS — fall back to the placeholder.

        This is the pre-#388 behaviour and it has to survive, because whether
        the hub puts the firmware sub-key in its status body varies by hub
        firmware.
        """
        from custom_components.aegis_ajax.update import _INSTALLED_VERSION_PLACEHOLDER

        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.installed_version == _INSTALLED_VERSION_PLACEHOLDER

    def test_installed_version_uses_the_hub_reported_version(self) -> None:
        # #388: the hub reports its running firmware on the status channel
        # (`hub_device.proto: HubDevice.Firmware.version = 0x37`), which the
        # gRPC snapshot never carried. When we have it, say it.
        coordinator = self._make_coordinator(None, firmware_version="2.41.116")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.installed_version == "2.41.116"

    def test_up_to_date_when_hub_version_known_and_nothing_queued(self) -> None:
        # HA renders `unknown` unless installed and latest are both set; equal
        # values are what produce "Up to date". With nothing queued the real
        # version has to appear on both sides, not the placeholder.
        coordinator = self._make_coordinator(None, firmware_version="2.41.116")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.latest_version == "2.41.116"
        assert entity.installed_version == entity.latest_version

    def test_pending_update_compares_against_the_real_version(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.42.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info, firmware_version="2.41.116")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.installed_version == "2.41.116"
        assert entity.latest_version == "2.42.0"

    def test_empty_hub_version_falls_back_to_placeholder(self) -> None:
        # A hub whose firmware omits the sub-key leaves an empty string.
        # That must behave exactly as before this change, not surface "".
        from custom_components.aegis_ajax.update import _INSTALLED_VERSION_PLACEHOLDER

        coordinator = self._make_coordinator(None, firmware_version="")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.installed_version == _INSTALLED_VERSION_PLACEHOLDER
        assert entity.latest_version == _INSTALLED_VERSION_PLACEHOLDER

    def test_release_summary_drops_the_caveat_once_version_is_known(self) -> None:
        # The old summary told users the installed version "is not exposed by
        # Ajax". Leaving that in place while showing one would be a lie.
        coordinator = self._make_coordinator(None, firmware_version="2.41.116")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        summary = entity.release_summary or ""
        assert "2.41.116" in summary
        assert "not exposed" not in summary

    def test_device_info_includes_hub_reported_firmware(self) -> None:
        coordinator = self._make_coordinator(None, firmware_version="2.41.116")
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert (entity.device_info or {}).get("sw_version") == "2.41.116"

    def test_device_info_picks_up_firmware_reported_after_construction(self) -> None:
        # The hub's firmware arrives over HTS, often after the entity has been
        # constructed. `device_info` must reflect it then, not stay frozen at
        # the construction-time value (#388).
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState

        coordinator = self._make_coordinator(None)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert "sw_version" not in (entity.device_info or {})

        coordinator.hub_network = {"002B1A51": HubNetworkState(firmware_version="2.41.116")}

        assert (entity.device_info or {}).get("sw_version") == "2.41.116"

    def test_device_info_is_none_when_hub_device_missing(self) -> None:
        coordinator = self._make_coordinator(None)
        coordinator.devices = {}
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.device_info is None

    def test_latest_version_reflects_pending_update(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.latest_version == "2.17.0"

    def test_latest_version_matches_installed_when_no_pending_update(self) -> None:
        """Up-to-date case: latest == installed so HA renders STATE_OFF, not unknown."""
        coordinator = self._make_coordinator(None)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.latest_version == entity.installed_version
        assert entity.in_progress is False

    def test_latest_version_falls_back_to_placeholder_on_empty_target(self) -> None:
        """Defensive: an empty target_version string is treated as 'no pending update'."""
        info = HubFirmwareUpdateInfo(target_version="", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.latest_version == entity.installed_version

    def test_in_progress_true_when_downloading(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_DOWNLOADING)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.in_progress is True

    def test_in_progress_false_when_not_started(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.in_progress is False

    def test_supported_features_excludes_install(self) -> None:
        """Read-only by design — no INSTALL feature; PROGRESS so HA honors in_progress."""
        from homeassistant.components.update import UpdateEntityFeature

        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert not (entity.supported_features & UpdateEntityFeature.INSTALL)
        assert entity.supported_features == UpdateEntityFeature.PROGRESS

    def test_state_attributes_report_in_progress_while_downloading(self) -> None:
        """Regression: without the PROGRESS feature flag, HA's

        `UpdateEntity.state_attributes` IGNORES the `in_progress`
        property and reports the internal install flag (always False
        here) — the property tests above can't catch that.
        """
        from homeassistant.components.update import ATTR_IN_PROGRESS

        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_DOWNLOADING)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.state_attributes[ATTR_IN_PROGRESS] is True

    def test_device_class_firmware(self) -> None:
        from homeassistant.components.update import UpdateDeviceClass

        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.device_class is UpdateDeviceClass.FIRMWARE

    def test_state_resolves_to_off_when_no_pending_update(self) -> None:
        """Smoke-check the full HA state computation lands on 'off' (up to date)."""
        from homeassistant.const import STATE_OFF

        coordinator = self._make_coordinator(None)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        # HA's UpdateEntity.state returns STATE_OFF when installed == latest.
        assert entity.state == STATE_OFF

    def test_release_summary_explains_up_to_date_semantics(self) -> None:
        """No pending update — release_summary clarifies it's not a positive confirmation."""
        coordinator = self._make_coordinator(None)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        summary = entity.release_summary
        assert summary is not None
        assert "not queued" in summary.lower()
        assert "not exposed" in summary.lower()

    def test_release_summary_names_target_version_when_update_queued(self) -> None:
        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        summary = entity.release_summary
        assert summary is not None
        assert "2.17.0" in summary
        assert "informational" in summary.lower()

    def test_state_resolves_to_on_when_pending_update(self) -> None:
        from homeassistant.const import STATE_ON

        info = HubFirmwareUpdateInfo(target_version="2.17.0", state=HUB_FW_STATE_NOT_STARTED)
        coordinator = self._make_coordinator(info)
        entity = AjaxHubFirmwareUpdate(coordinator, "002B1A51")
        assert entity.state == STATE_ON


class TestAsyncSetupEntry:
    @pytest.mark.asyncio
    async def test_setup_creates_one_entity_per_hub(self) -> None:
        from custom_components.aegis_ajax.api.models import Device, Space
        from custom_components.aegis_ajax.const import (
            ConnectionStatus,
            DeviceState,
            SecurityState,
        )
        from custom_components.aegis_ajax.update import async_setup_entry

        hub_id = "002B1A51"
        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.spaces = {
            "s1": Space(
                id="s1",
                hub_id=hub_id,
                name="Home",
                security_state=SecurityState.DISARMED,
                connection_status=ConnectionStatus.ONLINE,
                malfunctions_count=0,
            )
        }
        coordinator.devices = {
            hub_id: Device(
                id=hub_id,
                hub_id=hub_id,
                name="Hub",
                device_type="hub",
                room_id=None,
                group_id=None,
                state=DeviceState.ONLINE,
                malfunctions=0,
                bypassed=False,
                statuses={},
                battery=None,
            )
        }
        coordinator.hub_firmware_updates = {}
        entry = MagicMock(runtime_data=coordinator)
        async_add_entities = MagicMock()

        await async_setup_entry(MagicMock(), entry, async_add_entities)
        async_add_entities.assert_called_once()
        entities = async_add_entities.call_args[0][0]
        assert len(entities) == 1
        assert isinstance(entities[0], AjaxHubFirmwareUpdate)

    @pytest.mark.asyncio
    async def test_setup_skips_spaces_without_hub_device(self) -> None:
        from custom_components.aegis_ajax.api.models import Space
        from custom_components.aegis_ajax.const import ConnectionStatus, SecurityState
        from custom_components.aegis_ajax.update import async_setup_entry

        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.spaces = {
            "s1": Space(
                id="s1",
                hub_id="HUB1",
                name="Home",
                security_state=SecurityState.DISARMED,
                connection_status=ConnectionStatus.ONLINE,
                malfunctions_count=0,
            )
        }
        # No hub device yet — the hub-id-keyed lookup misses.
        coordinator.devices = {}
        coordinator.hub_firmware_updates = {}
        entry = MagicMock(runtime_data=coordinator)
        async_add_entities = MagicMock()

        await async_setup_entry(MagicMock(), entry, async_add_entities)
        entities = async_add_entities.call_args[0][0]
        assert entities == []


def _make_device(
    device_id: str, device_type: str = "door_protect", name: str = "Front Door"
) -> Device:
    from custom_components.aegis_ajax.api.models import Device
    from custom_components.aegis_ajax.const import DeviceState

    return Device(
        id=device_id,
        hub_id="002B1A51",
        name=name,
        device_type=device_type,
        room_id=None,
        group_id=None,
        state=DeviceState.ONLINE,
        malfunctions=0,
        bypassed=False,
        statuses={},
        battery=None,
    )


class TestAjaxDeviceFirmwareUpdate:
    @staticmethod
    def _make_coordinator(
        info: DeviceFirmwareUpdateInfo | None,
        device_id: str = "AA11BB22",
    ) -> MagicMock:
        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.devices = {device_id: _make_device(device_id)}
        coordinator.device_firmware_updates = {device_id: info} if info else {}
        return coordinator

    def test_unique_id_namespaced_by_device(self) -> None:
        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity._attr_unique_id == "aegis_ajax_AA11BB22_firmware"

    def test_disabled_by_default(self) -> None:
        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.entity_registry_enabled_default is False

    def test_installed_version_is_constant_placeholder(self) -> None:
        from custom_components.aegis_ajax.update import _INSTALLED_VERSION_PLACEHOLDER

        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.installed_version == _INSTALLED_VERSION_PLACEHOLDER

    def test_latest_version_reflects_pending_update(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="6.62.3", state=DEVICE_FW_STATE_NOT_STARTED
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.latest_version == "6.62.3"

    def test_latest_version_matches_installed_when_no_pending_update(self) -> None:
        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.latest_version == entity.installed_version
        assert entity.in_progress is False

    def test_latest_version_falls_back_on_empty_target(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="", state=DEVICE_FW_STATE_NOT_STARTED
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.latest_version == entity.installed_version

    def test_in_progress_true_when_downloading(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22",
            target_version="6.62.3",
            state=DEVICE_FW_STATE_DOWNLOADING,
            progress=42,
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.in_progress is True
        assert entity.update_percentage == 42

    def test_in_progress_true_when_installing_without_percentage(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="6.62.3", state=DEVICE_FW_STATE_INSTALLING
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.in_progress is True
        # No progress signal during install → indeterminate bar.
        assert entity.update_percentage is None

    def test_in_progress_false_when_downloaded(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="6.62.3", state=DEVICE_FW_STATE_DOWNLOADED
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.in_progress is False
        assert entity.update_percentage is None

    def test_supported_features_excludes_install(self) -> None:
        from homeassistant.components.update import UpdateEntityFeature

        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert not (entity.supported_features & UpdateEntityFeature.INSTALL)
        assert entity.supported_features == UpdateEntityFeature.PROGRESS

    def test_state_attributes_report_progress_while_downloading(self) -> None:
        """Regression: HA's `UpdateEntity.state_attributes` only honors the

        `in_progress`/`update_percentage` properties when the PROGRESS
        feature flag is declared — with `UpdateEntityFeature(0)` both
        were silently ignored (in_progress always False, percentage
        always None) and no property-level test could catch it.
        """
        from homeassistant.components.update import (
            ATTR_IN_PROGRESS,
            ATTR_UPDATE_PERCENTAGE,
        )

        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22",
            target_version="6.62.3",
            state=DEVICE_FW_STATE_DOWNLOADING,
            progress=42,
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        attrs = entity.state_attributes
        assert attrs[ATTR_IN_PROGRESS] is True
        assert attrs[ATTR_UPDATE_PERCENTAGE] == 42

    def test_available_requires_device_presence(self) -> None:
        """A device removed from the hub must flip its orphan entity to

        unavailable instead of reporting "Up to date" forever (HA never
        evicts orphan registry entries on its own).
        """
        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        coordinator.last_update_success = True
        assert entity.available is True
        coordinator.devices = {}
        assert entity.available is False

    def test_info_lookup_is_casing_proof(self) -> None:
        """Regression: the update map keys come from `streamHubObject`

        while entities key off `Device.id` from the devices snapshot —
        two services whose hex-id casing is not guaranteed to match.
        Both sides normalize via `.upper()`.
        """
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="6.62.3", state=DEVICE_FW_STATE_NOT_STARTED
        )
        coordinator = self._make_coordinator(info, device_id="aa11bb22")
        # Map keyed uppercase (as the coordinator writes it); entity was
        # created from a lowercase snapshot id.
        coordinator.device_firmware_updates = {"AA11BB22": info}
        entity = AjaxDeviceFirmwareUpdate(coordinator, "aa11bb22")
        assert entity.latest_version == "6.62.3"

    def test_failed_state_surfaces_in_release_summary(self) -> None:
        """A failed install is the case the user most needs to see —

        it must not render as an ordinary pending update.
        """
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22",
            target_version="6.62.3",
            state=DEVICE_FW_STATE_FAILED,
            is_critical=True,
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        # Still an update pending from HA's point of view…
        assert entity.latest_version == "6.62.3"
        summary = entity.release_summary
        assert summary is not None
        # …but the summary says the last attempt failed.
        assert "failed" in summary.lower()
        assert "critical" in summary.lower()

    def test_completed_state_renders_up_to_date(self) -> None:
        """A completed update lingers in the snapshot for up to an hour;

        it must render as "Up to date", not as a pending update.
        """
        from homeassistant.const import STATE_OFF

        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22",
            target_version="6.62.3",
            state=DEVICE_FW_STATE_COMPLETED,
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.latest_version == entity.installed_version
        assert entity.state == STATE_OFF
        summary = entity.release_summary
        assert summary is not None
        assert "installed" in summary.lower()

    def test_device_class_firmware(self) -> None:
        from homeassistant.components.update import UpdateDeviceClass

        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.device_class is UpdateDeviceClass.FIRMWARE

    def test_state_off_when_no_pending_update(self) -> None:
        from homeassistant.const import STATE_OFF

        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.state == STATE_OFF

    def test_state_on_when_pending_update(self) -> None:
        from homeassistant.const import STATE_ON

        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22", target_version="6.62.3", state=DEVICE_FW_STATE_NOT_STARTED
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        assert entity.state == STATE_ON

    def test_release_summary_explains_up_to_date(self) -> None:
        coordinator = self._make_coordinator(None)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        summary = entity.release_summary
        assert summary is not None
        assert "not queued" in summary.lower()
        assert "device" in summary.lower()

    def test_release_summary_flags_critical_update(self) -> None:
        info = DeviceFirmwareUpdateInfo(
            device_id="AA11BB22",
            target_version="6.62.3",
            state=DEVICE_FW_STATE_NOT_STARTED,
            is_critical=True,
        )
        coordinator = self._make_coordinator(info)
        entity = AjaxDeviceFirmwareUpdate(coordinator, "AA11BB22")
        summary = entity.release_summary
        assert summary is not None
        assert "6.62.3" in summary
        assert "critical" in summary.lower()


class TestAsyncSetupEntryDeviceFirmware:
    @pytest.mark.asyncio
    async def test_setup_creates_disabled_entity_per_non_hub_device(self) -> None:
        from custom_components.aegis_ajax.api.models import Device, Space
        from custom_components.aegis_ajax.const import (
            ConnectionStatus,
            DeviceState,
            SecurityState,
        )
        from custom_components.aegis_ajax.update import async_setup_entry

        hub_id = "002B1A51"
        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.spaces = {
            "s1": Space(
                id="s1",
                hub_id=hub_id,
                name="Home",
                security_state=SecurityState.DISARMED,
                connection_status=ConnectionStatus.ONLINE,
                malfunctions_count=0,
            )
        }
        coordinator.devices = {
            hub_id: Device(
                id=hub_id,
                hub_id=hub_id,
                name="Hub",
                device_type="hub",
                room_id=None,
                group_id=None,
                state=DeviceState.ONLINE,
                malfunctions=0,
                bypassed=False,
                statuses={},
                battery=None,
            ),
            "AA11BB22": _make_device("AA11BB22"),
            "CC33DD44": _make_device("CC33DD44", name="Kitchen Motion"),
        }
        coordinator.hub_firmware_updates = {}
        coordinator.device_firmware_updates = {}
        entry = MagicMock(runtime_data=coordinator)
        async_add_entities = MagicMock()

        await async_setup_entry(MagicMock(), entry, async_add_entities)
        entities = async_add_entities.call_args[0][0]
        hub_entities = [e for e in entities if isinstance(e, AjaxHubFirmwareUpdate)]
        device_entities = [e for e in entities if isinstance(e, AjaxDeviceFirmwareUpdate)]
        assert len(hub_entities) == 1
        # One per non-hub device; the hub device is excluded.
        assert len(device_entities) == 2
        assert all(e.entity_registry_enabled_default is False for e in device_entities)

    @pytest.mark.asyncio
    async def test_unrecognized_hub_type_gets_no_duplicate_entity(self) -> None:
        """Regression: a hub model newer than the vendored proto parses as

        device_type "unknown", escaping the `startswith("hub")` filter.
        The `device_id in seen` guard must still keep it out of the
        per-device loop — otherwise two entities share one unique_id and
        HA drops one.
        """
        from custom_components.aegis_ajax.api.models import Space
        from custom_components.aegis_ajax.const import ConnectionStatus, SecurityState
        from custom_components.aegis_ajax.update import async_setup_entry

        hub_id = "002B1A51"
        coordinator = MagicMock()
        coordinator.rooms = {}
        coordinator.spaces = {
            "s1": Space(
                id="s1",
                hub_id=hub_id,
                name="Home",
                security_state=SecurityState.DISARMED,
                connection_status=ConnectionStatus.ONLINE,
                malfunctions_count=0,
            )
        }
        coordinator.devices = {
            # Future hub model → oneof unmatched → device_type "unknown".
            hub_id: _make_device(hub_id, device_type="unknown", name="Hub Mega"),
        }
        coordinator.hub_firmware_updates = {}
        coordinator.device_firmware_updates = {}
        entry = MagicMock(runtime_data=coordinator)
        async_add_entities = MagicMock()

        await async_setup_entry(MagicMock(), entry, async_add_entities)
        entities = async_add_entities.call_args[0][0]
        assert len([e for e in entities if isinstance(e, AjaxHubFirmwareUpdate)]) == 1
        assert [e for e in entities if isinstance(e, AjaxDeviceFirmwareUpdate)] == []
