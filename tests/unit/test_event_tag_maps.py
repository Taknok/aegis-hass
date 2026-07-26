"""Descriptor-validated checks on the push event vocabularies.

Every mapping the push parser relies on is asserted against the vendored
proto descriptors, so a renamed, renumbered or newly added Ajax field
fails a test instead of silently producing a dead branch — the failure
mode that hid #339 for two years (`LightDeviceStatus.statuses` had no
`tamper` case, so the parser branch could never run and the MagicMock
test stayed green forever).

The collision checks also encode *why* the parser routes by content type:
hub and space tags share field numbers, so the qualifier's own bytes can
never identify which vocabulary it belongs to.
"""

from __future__ import annotations

import pytest
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.hub import (
    tag_pb2 as hub_tag_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.smartlock import (
    tag_pb2 as smartlock_tag_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.space import (
    tag_pb2 as space_tag_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.video import (
    tag_pb2 as video_tag_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification import (
    content_pb2,
)

from custom_components.aegis_ajax.const import (
    HUB_EVENT_TAG_MAP,
    RAW_TAG_TO_GROUP_SECURITY_STATE,
    RAW_TAG_TO_SECURITY_STATE,
    SECURITY_STATE_EVENT_TYPES,
    SMARTLOCK_EVENT_TAG_MAP,
    SPACE_EVENT_TAG_MAP,
    TAG_PRIORITY,
    VIDEO_EVENT_TAG_MAP,
)
from custom_components.aegis_ajax.notification_event_parser import (
    _CONTENT_TAG_MAPS,
    _UNMAPPED_CONTENT_CASES,
)


def _field_numbers(tag_message: type) -> dict[str, int]:
    return {f.name: f.number for f in tag_message.DESCRIPTOR.fields}


_HUB_FIELDS = _field_numbers(hub_tag_pb2.HubEventTag)
_SPACE_FIELDS = _field_numbers(space_tag_pb2.SpaceEventTag)
_VIDEO_FIELDS = _field_numbers(video_tag_pb2.VideoEventTag)
_SMARTLOCK_FIELDS = _field_numbers(smartlock_tag_pb2.SmartLockEventTag)

_VOCABULARIES = {
    "hub": (HUB_EVENT_TAG_MAP, _HUB_FIELDS),
    "space": (SPACE_EVENT_TAG_MAP, _SPACE_FIELDS),
    "video": (VIDEO_EVENT_TAG_MAP, _VIDEO_FIELDS),
    "smartlock": (SMARTLOCK_EVENT_TAG_MAP, _SMARTLOCK_FIELDS),
}
_ALL_MAPPED_TAGS = set().union(*(set(m) for m, _ in _VOCABULARIES.values()))


class TestTagMapsMatchTheProtos:
    @pytest.mark.parametrize("vocabulary", sorted(_VOCABULARIES))
    def test_every_mapped_tag_exists_in_its_proto(self, vocabulary: str) -> None:
        tag_map, proto_fields = _VOCABULARIES[vocabulary]

        unknown = sorted(set(tag_map) - set(proto_fields))

        assert not unknown, f"{vocabulary} map references non-existent tags: {unknown}"

    def test_every_prioritised_tag_is_a_real_mapped_tag(self) -> None:
        # A typo here doesn't raise: `TAG_PRIORITY.get(tag, 0)` silently
        # weights the tag at 0, so a real incident would lose to a state
        # transition instead of winning.
        unknown = sorted(set(TAG_PRIORITY) - _ALL_MAPPED_TAGS)

        assert not unknown, f"TAG_PRIORITY references unmapped tags: {unknown}"

    @pytest.mark.parametrize(
        "map_name",
        ["RAW_TAG_TO_SECURITY_STATE", "RAW_TAG_TO_GROUP_SECURITY_STATE"],
    )
    def test_security_state_tags_are_reachable(self, map_name: str) -> None:
        # These maps are keyed on the raw tag the parser reports, so an
        # entry whose tag no vocabulary maps can never be looked up: the
        # security state would silently stop following the push.
        state_map = {
            "RAW_TAG_TO_SECURITY_STATE": RAW_TAG_TO_SECURITY_STATE,
            "RAW_TAG_TO_GROUP_SECURITY_STATE": RAW_TAG_TO_GROUP_SECURITY_STATE,
        }[map_name]

        unreachable = sorted(set(state_map) - _ALL_MAPPED_TAGS)

        assert not unreachable, f"{map_name} keys never produced by the parser: {unreachable}"

    def test_security_state_event_types_are_produced_by_some_tag(self) -> None:
        # `SECURITY_STATE_EVENT_TYPES` gates the authoritative snapshot
        # nudge; an event type no tag maps to would make that dead code.
        produced = set()
        for tag_map, _ in _VOCABULARIES.values():
            produced |= set(tag_map.values())

        assert not set(SECURITY_STATE_EVENT_TYPES) - produced


class TestContentCaseCoverage:
    """Every `NotificationContent` case must be handled explicitly."""

    @staticmethod
    def _content_cases() -> set[str]:
        return {f.name for f in content_pb2.NotificationContent.DESCRIPTOR.oneofs[0].fields}

    def test_mapped_cases_are_real_oneof_cases(self) -> None:
        # A typo would route real pushes to the fallback scan, which is
        # exactly the cross-decoding path this mapping exists to avoid.
        unknown = sorted(set(_CONTENT_TAG_MAPS) - self._content_cases())

        assert not unknown, f"_CONTENT_TAG_MAPS references non-existent content cases: {unknown}"

    def test_every_content_case_is_accounted_for(self) -> None:
        # New Ajax content types must be an explicit decision — mapped to a
        # vocabulary or listed as knowingly unmapped — not silently
        # inherited by whatever the fallback happens to do.
        handled = set(_CONTENT_TAG_MAPS) | set(_UNMAPPED_CONTENT_CASES)

        unhandled = sorted(self._content_cases() - handled)

        assert not unhandled, f"Unhandled NotificationContent cases: {unhandled}"

    def test_mapped_and_unmapped_cases_do_not_overlap(self) -> None:
        assert not set(_CONTENT_TAG_MAPS) & set(_UNMAPPED_CONTENT_CASES)

    def test_each_mapped_case_actually_carries_a_qualifier(self) -> None:
        by_name = {f.name: f for f in content_pb2.NotificationContent.DESCRIPTOR.oneofs[0].fields}

        for case in _CONTENT_TAG_MAPS:
            sub_fields = {f.name for f in by_name[case].message_type.fields}
            assert "qualifier" in sub_fields, f"{case} carries no qualifier"


class TestVocabulariesCollideByFieldNumber:
    """The reason the content case has to decide the qualifier type.

    If these collisions ever disappear (Ajax renumbering the tag protos),
    the routing comments in `notification_event_parser` need revisiting —
    which is what a failure here means, not a bug in the parser.
    """

    def test_mapped_hub_tags_collide_with_mapped_space_tags(self) -> None:
        space_by_number = {number: name for name, number in _SPACE_FIELDS.items()}

        collisions = {
            name: space_by_number[_HUB_FIELDS[name]]
            for name in HUB_EVENT_TAG_MAP
            if space_by_number.get(_HUB_FIELDS[name]) in SPACE_EVENT_TAG_MAP
        }

        # The four that were relabelled in the wild: door_opened → arm,
        # device_communication_loss → arm, malfunction → arm_night,
        # tamper_opened → disarm.
        assert collisions, "expected hub/space field-number collisions"
        assert collisions["tamper_opened"] == "space_group_duress_disarmed"
        assert collisions["door_opened"] == "space_armed"

    def test_hub_arm_disarm_tags_do_not_collide_with_mapped_space_tags(self) -> None:
        # Hub-level arm/disarm sit at fields 83-96, which no *mapped* space
        # tag occupies — that is why arm/disarm kept working while door and
        # tamper events came out mangled. Documented so the asymmetry in
        # the bug reports stays explainable. (Note `max()` is useless here:
        # SpaceEventTag has a sentinel field at 9999.)
        mapped_space_numbers = {
            number for name, number in _SPACE_FIELDS.items() if name in SPACE_EVENT_TAG_MAP
        }

        for tag, event_type in HUB_EVENT_TAG_MAP.items():
            if event_type in SECURITY_STATE_EVENT_TYPES:
                assert _HUB_FIELDS[tag] not in mapped_space_numbers, tag
