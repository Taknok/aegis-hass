"""Diagnostics support for Ajax Security."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD
from homeassistant.util import dt as dt_util

from custom_components.aegis_ajax.api.models import (
    device_deactivation_kinds,
    is_device_deactivated,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from custom_components.aegis_ajax import AjaxCobrandedConfigEntry
    from custom_components.aegis_ajax.coordinator import AjaxCobrandedCoordinator

TO_REDACT = {
    CONF_PASSWORD,
    "password_hash",
    "email",
    "session_token",
    "device_id",
    "push_token",
    "fcm_api_key",
    "fcm_project_id",
    "fcm_app_id",
    "fcm_sender_id",
}


def _group_name(coordinator: AjaxCobrandedCoordinator, group_id: str | None) -> str | None:
    """Resolve an Ajax group id to its name across every space (#366).

    Groups hang off spaces, so the lookup has to walk them; a device's
    `group_id` alone is meaningless to a reader of the dump.
    """
    if not group_id:
        return None
    for space in coordinator.spaces.values():
        group = space.get_group(group_id)
        if group is not None:
            return group.name
    return None


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: AjaxCobrandedConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data

    # Probe the VideoEdge ONVIF/RTSP settings for each distinct video_edge_id
    # seen across the devices' source lists (#282). Read-only and best-effort:
    # it maps what's available towards a real camera entity without affecting
    # normal operation. Skipped entirely when there are no video devices.
    video_edge_kinds: dict[str, set[str]] = {}
    for device in coordinator.devices.values():
        for source in device.statuses.get("video_sources", []):
            ve_id = source.get("video_edge_id")
            if ve_id:
                video_edge_kinds.setdefault(ve_id, set()).add(source.get("kind"))

    video_edge_probe: dict[str, Any] = {}
    for ve_id, kinds in video_edge_kinds.items():
        settings: dict[str, Any] | None = None
        owning_space: str | None = None
        for space_id in coordinator.spaces:
            settings = await coordinator.devices_api.get_video_edge_onvif_rtsp_settings(
                space_id, ve_id
            )
            # Stop at the space that actually owns this VideoEdge.
            if settings is not None and "error" not in settings:
                owning_space = space_id
                break
        # Read the LAN IP / MAC (#282) so the dump has the full connection info
        # (IP + ONVIF/RTSP ports) to point HA's native ONVIF integration at.
        network = await coordinator.devices_api.get_video_edge_network(
            owning_space or next(iter(coordinator.spaces), ""), ve_id
        )
        # Read-only WebRTC feasibility probe (#322): does the account get past
        # the permission gate to start the app-style remote live stream? PII-free
        # (no credentials/URLs/SDP); no media is negotiated. This is the go/no-go
        # signal for a future camera entity for cloud-only (VPS) Home Assistant.
        webrtc = await coordinator.devices_api.probe_webrtc_initiate(
            owning_space or next(iter(coordinator.spaces), ""), ve_id
        )
        video_edge_probe[ve_id] = {
            "kinds": sorted(k for k in kinds if k),
            **(settings or {"error": "not_probed"}),
            "network": network,
            "webrtc": webrtc,
        }

    return {
        "entry_data": async_redact_data(dict(entry.data), TO_REDACT),
        "spaces": {
            sid: {
                "name": s.name,
                "security_state": s.security_state.name,
                "online": s.is_online,
                "malfunctions": s.malfunctions_count,
                "group_mode_enabled": s.group_mode_enabled,
                "night_mode_enabled": s.night_mode_enabled,
                "chime_status": s.chime_status.name,
                "groups": [
                    {
                        "id": g.id,
                        "name": g.name,
                        "security_state": g.security_state.name,
                    }
                    for g in s.groups
                ],
            }
            for sid, s in coordinator.spaces.items()
        },
        "devices": {
            did: {
                "name": d.name,
                "type": d.device_type,
                "state": d.state,
                "online": d.is_online,
                "malfunctions": d.malfunctions,
                "bypassed": d.bypassed,
                # Ajax group membership (#366), the per-device direction of
                # what the group alarm panel lists. `None` on a space with
                # group mode off, where the concept does not apply. Distinct
                # from the room, which a device has independently.
                "group_id": d.group_id,
                "group_name": _group_name(coordinator, d.group_id),
                # What the bypass switch actually shows (#338). `bypassed` is
                # only one of the two sources: a device deactivated from the
                # Ajax app leaves it False and reports `*_deactivation_*`
                # statuses instead, so both are dumped side by side.
                "deactivated": is_device_deactivated(d),
                "deactivation_kinds": device_deactivation_kinds(d),
                "battery": (
                    {"level": d.battery.level, "low": d.battery.is_low} if d.battery else None
                ),
                "statuses": list(d.statuses.keys()),
                # Raw video-channel identity (#282/#290): the `About.Type`
                # value behind a `video_edge_*` device_type and the
                # source list (primary / nvr / cloud_archive + ids) that
                # links a camera channel to the NVR re-publishing it.
                # Keys absent on non-video devices.
                **(
                    {"video_edge_type": d.statuses["video_edge_type"]}
                    if "video_edge_type" in d.statuses
                    else {}
                ),
                **(
                    {"video_sources": d.statuses["video_sources"]}
                    if "video_sources" in d.statuses
                    else {}
                ),
                # LifeQuality environmental readings (#302): dump the actual
                # `lq_*` values (temperature / humidity / CO₂ + threshold/fault
                # enums) so a diagnostics download confirms which data path a
                # real device uses and in what units, before sensors are added.
                **{k: v for k, v in d.statuses.items() if k.startswith("lq_")},
            }
            for did, d in coordinator.devices.items()
        },
        "keyfobs": {
            kid: {
                "name": k.name,
                "index": k.index,
                "active": k.active,
                "flags_hex": k.flags_hex,
            }
            for kid, k in coordinator.keyfobs.items()
        },
        "video_edge_onvif_rtsp": video_edge_probe,
        # Firmware update state feeding the `update.*` entities (project
        # rule: every entity-driving field is dumped here). Both maps are
        # empty most of the time — Ajax only lists a hub/device while an
        # update is queued or in flight.
        "hub_firmware_updates": {
            hid: {"target_version": fw.target_version, "state": fw.state}
            for hid, fw in coordinator.hub_firmware_updates.items()
        },
        "device_firmware_updates": {
            did: {
                "target_version": dfu.target_version,
                "state": dfu.state,
                "progress": dfu.progress,
                "is_critical": dfu.is_critical,
            }
            for did, dfu in coordinator.device_firmware_updates.items()
        },
        # Last press epoch per Button, which is what drives the Button press
        # event entity (#348). Rendered as an ISO timestamp because that is what
        # makes it checkable: if the entity never fires, this says whether the
        # hub is reporting presses at all and when the last one landed.
        "button_press_epochs": {
            did: dt_util.utc_from_timestamp(seconds).isoformat()
            for did, seconds in coordinator._button_press_epochs.items()
        },
        "stream_tasks": len(coordinator._stream_tasks),
        "notification_listener": coordinator.notification_listener is not None,
    }
