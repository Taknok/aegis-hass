"""Source identity must be decoded against its own vocabulary (#367).

`_extract_source_info` located the event's source by scanning the payload for
a `HubNotificationSource` and mapping its numeric `type` through the **hub**
vocabulary. But all four `*NotificationSource` messages share an identical
wire layout (`1 type` varint, `2 id` string, `3 name` string), so a
`SpaceNotificationSource` — which is what a whole-space arm/disarm carries —
parses cleanly as the hub variant and its type gets translated with the wrong
dictionary. The vocabularies disagree on every value: `2` is `HUB_PLUS` in the
hub one and `SPACE_MEMBER` in the space one.

Same class of defect as #320/#339, where event *tags* were being resolved
against the wrong vocabulary. That was fixed by letting the content wrapper
identify the type; the source field never got the same treatment.

Real protos throughout — a MagicMock source cannot reproduce a cross-decode
that exists precisely because two real messages share a wire shape.
"""

from __future__ import annotations

from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.hub import (
    qualifier_pb2 as hub_qualifier_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.event.space import (
    qualifier_pb2 as space_qualifier_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification import (
    content_pb2,
    notification_pb2,
    space_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification.hub import (
    content_pb2 as hub_content_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification.hub import (
    origin_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification.hub import (
    source_pb2 as hub_source_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification.space import (
    content_pb2 as space_content_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.commonmodels.notification.space import (
    source_pb2 as space_source_pb2,
)
from systems.ajax.api.ecosystem.v2.communicationsvc.mobile.service.push_notification_dispatch import (  # noqa: E501
    event_pb2,
)

from custom_components.aegis_ajax import notification_event_parser as parser

_SPACE_ID = "aabb11223344556677889900"


def _wrap(content: content_pb2.NotificationContent) -> bytes:
    notification = notification_pb2.Notification(
        id="A" * 64,
        space=space_pb2.NotificationSpace(id=_SPACE_ID, name="Casa"),
        content=content,
    )
    return event_pb2.PushNotificationDispatchEvent(notification=notification).SerializeToString()


def _space_push(source: space_source_pb2.SpaceNotificationSource) -> bytes:
    """A whole-space disarm attributed to `source`."""
    qualifier = space_qualifier_pb2.SpaceEventQualifier()
    qualifier.tag.space_disarmed.SetInParent()
    return _wrap(
        content_pb2.NotificationContent(
            space_notification_content=space_content_pb2.SpaceNotificationContent(
                qualifier=qualifier, space_source=source
            )
        )
    )


def _hub_push(source: hub_source_pb2.HubNotificationSource) -> bytes:
    """A hub-vocabulary door-open attributed to `source`."""
    qualifier = hub_qualifier_pb2.HubEventQualifier()
    qualifier.tag.door_opened.SetInParent()
    return _wrap(
        content_pb2.NotificationContent(
            hub_notification_content=hub_content_pb2.HubNotificationContent(
                origin=origin_pb2.HubOrigin(hex_id="E5F6A7B8", name="Hub 2 Plus"),
                qualifier=qualifier,
                source=source,
            )
        )
    )


class TestSpaceSourceUsesSpaceVocabulary:
    def test_disarm_by_a_person_is_labelled_space_member(self) -> None:
        """#362/#359 want to know *who* armed. `2` here means SPACE_MEMBER;
        reading it with the hub vocabulary yields the meaningless `HUB_PLUS`.
        """
        raw = _space_push(
            space_source_pb2.SpaceNotificationSource(type=2, id="00ABCDEF", name="Carlos Lopez")
        )

        info = parser._extract_source_info(raw)

        assert info["device_name"] == "Carlos Lopez"
        assert info["device_type"] == "SPACE_MEMBER"

    def test_disarm_by_a_standalone_device_is_not_labelled_hub_3(self) -> None:
        """`7` is STANDALONE_DEVICE in the space vocabulary and HUB_3 in the
        hub one — a second value proving the table, not just one lucky row.
        """
        raw = _space_push(
            space_source_pb2.SpaceNotificationSource(type=7, id="30D39295", name="Brelok 2")
        )

        info = parser._extract_source_info(raw)

        assert info["device_name"] == "Brelok 2"
        assert info["device_type"] == "STANDALONE_DEVICE"


class TestHubSourceStillUsesHubVocabulary:
    def test_hub_content_source_is_unchanged(self) -> None:
        """The path that already worked must keep working: `26` is
        DOOR_PROTECT in the hub vocabulary.
        """
        raw = _hub_push(
            hub_source_pb2.HubNotificationSource(type=26, id="003AE89B", name="FIN VESTIDOR")
        )

        info = parser._extract_source_info(raw)

        assert info["device_name"] == "FIN VESTIDOR"
        assert info["device_type"] == "DOOR_PROTECT"


class TestSpaceContentFallsBackToHubSource:
    def test_hub_source_is_used_when_no_space_source(self) -> None:
        """`SpaceNotificationContent` carries both `space_source` and
        `hub_source`. With only the latter set, it must be read against the
        hub vocabulary rather than the space one.
        """
        qualifier = space_qualifier_pb2.SpaceEventQualifier()
        qualifier.tag.space_disarmed.SetInParent()
        raw = _wrap(
            content_pb2.NotificationContent(
                space_notification_content=space_content_pb2.SpaceNotificationContent(
                    qualifier=qualifier,
                    hub_source=hub_source_pb2.HubNotificationSource(
                        type=36, id="30D39295", name="Brelok 2"
                    ),
                )
            )
        )

        info = parser._extract_source_info(raw)

        assert info["device_name"] == "Brelok 2"
        assert info["device_type"] == "SPACE_CONTROL"


class TestUnstructuredPayloadStillScans:
    def test_non_dispatch_payload_falls_back_to_the_scan(self) -> None:
        """Payloads that don't decode as a dispatch notification must keep
        resolving through the legacy scan rather than returning nothing.
        """
        source = hub_source_pb2.HubNotificationSource(
            type=26, id="003AE89B", name="FIN VESTIDOR"
        ).SerializeToString()

        info = parser._extract_source_info(b"\xff\xff" + source)

        assert info.get("device_name") == "FIN VESTIDOR"
