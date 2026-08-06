"""What the refreshed `HubDevice.device` oneof does and does not cover (#408).

These assertions run against the compiled descriptor, so they pin decisions
that a future regeneration could quietly undo — both the families we gained
and the ones we deliberately left out. They also pin the boundary of what the
refresh unlocked, because a modelled case is not a promise of data: a family
whose message carries only its arming state resolves fine and reads as empty,
which is exactly how #229 was misdiagnosed the first time.
"""

from __future__ import annotations

# Wire up the proto search path before any `systems.*` import.
from custom_components.aegis_ajax.api import _proto_path as _proto_path  # noqa: E402, F401


def _hub_device_descriptor():  # noqa: ANN202
    from systems.ajax.api.ecosystem.v2.hubsvc.commonmodels.device import hub_device_pb2

    return hub_device_pb2.HubDevice.DESCRIPTOR


def _case(name: str):  # noqa: ANN202
    return _hub_device_descriptor().fields_by_name.get(name)


def _parts(name: str) -> set[str]:
    field = _case(name)
    assert field is not None, f"{name} is not modelled"
    return {f.name for f in field.message_type.fields}


class TestModelledFamilies:
    def test_covers_the_families_measured_as_unreadable(self) -> None:
        """The five @wip3out3r opened the endpoint for, one at a time (#408)."""
        for name in (
            "motion_protect_curtain",
            "door_protect_plus",
            "space_control",
            "transmitter",
            "range_extender2",
        ):
            assert _case(name) is not None, f"{name} should be modelled"

    def test_the_oneof_did_not_shrink(self) -> None:
        cases = _hub_device_descriptor().oneofs_by_name["device"].fields
        assert len(cases) >= 107


class TestDeliberatelyUnmodelledFamilies:
    """Four families are left out on purpose: part of their definition is not
    available to us, and a placeholder would decode to an empty message —
    indistinguishable from a device that reports nothing. Leaving them out
    routes them to the unknown-case probe instead, which names them."""

    def test_families_with_unavailable_parts_stay_out(self) -> None:
        for name in (
            "life_quality",
            "life_quality_lite",
            "roller_shutter_ls",
            "roller_shutter_ws",
        ):
            assert _case(name) is None, (
                f"{name} was modelled: check its parts are genuinely available "
                "rather than stubbed, or this is a silent regression to an "
                "empty message"
            )


class TestWhatTheRefreshUnlocked:
    def test_space_control_exposes_its_bypass_state(self) -> None:
        """A SpaceControl reported as a modelled device carries `bypass_part`
        directly — the deactivation read #311 has been waiting for, and one
        #338 can use."""
        assert "bypass_part" in _parts("space_control")

    def test_door_protect_still_carries_the_bypass_path(self) -> None:
        assert "common_jeweller_part" in _parts("door_protect")


class TestWhatTheRefreshDidNotUnlock:
    """Honest boundaries. Each of these families now resolves, and each still
    has nothing worth reading — asserting it stops the case list being mistaken
    for a capability list."""

    def test_outdoor_curtains_still_report_no_temperature(self) -> None:
        """#229's workaround stays: these carry only their arming state, so the
        temperature still has to come from the hub status stream."""
        for name in (
            "motion_protect_curtain_outdoor_base",
            "motion_protect_curtain_outdoor_plus",
            "dual_curtain_outdoor",
        ):
            assert "device_temperature" not in _parts(name)

    def test_the_stub_families_carry_no_bypass_data(self) -> None:
        for name in ("door_protect_plus", "motion_protect_curtain", "transmitter"):
            assert "common_jeweller_part" not in _parts(name)
