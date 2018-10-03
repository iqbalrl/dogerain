"""File generated by TLObjects' generator. All changes will be ERASED"""
from ...tl.tlobject import TLObject
from typing import Optional, List, Union, TYPE_CHECKING
import os
import struct
if TYPE_CHECKING:
    from ...tl.types import TypeChat, TypeUser, TypeChannelAdminLogEvent, TypeChannelParticipant



class AdminLogResults(TLObject):
    CONSTRUCTOR_ID = 0xed8af74d
    SUBCLASS_OF_ID = 0x51f076bc

    def __init__(self, events, chats, users):
        """
        :param List[TypeChannelAdminLogEvent] events:
        :param List[TypeChat] chats:
        :param List[TypeUser] users:

        Constructor for channels.AdminLogResults: Instance of AdminLogResults.
        """
        self.events = events  # type: List[TypeChannelAdminLogEvent]
        self.chats = chats  # type: List[TypeChat]
        self.users = users  # type: List[TypeUser]

    def to_dict(self):
        return {
            '_': 'AdminLogResults',
            'events': [] if self.events is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.events],
            'chats': [] if self.chats is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.chats],
            'users': [] if self.users is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.users]
        }

    def __bytes__(self):
        return b''.join((
            b'M\xf7\x8a\xed',
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.events)),b''.join(bytes(x) for x in self.events),
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.chats)),b''.join(bytes(x) for x in self.chats),
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.users)),b''.join(bytes(x) for x in self.users),
        ))

    @classmethod
    def from_reader(cls, reader):
        reader.read_int()
        _events = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _events.append(_x)

        reader.read_int()
        _chats = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _chats.append(_x)

        reader.read_int()
        _users = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _users.append(_x)

        return cls(events=_events, chats=_chats, users=_users)


class ChannelParticipant(TLObject):
    CONSTRUCTOR_ID = 0xd0d9b163
    SUBCLASS_OF_ID = 0x6658151a

    def __init__(self, participant, users):
        """
        :param TypeChannelParticipant participant:
        :param List[TypeUser] users:

        Constructor for channels.ChannelParticipant: Instance of ChannelParticipant.
        """
        self.participant = participant  # type: TypeChannelParticipant
        self.users = users  # type: List[TypeUser]

    def to_dict(self):
        return {
            '_': 'ChannelParticipant',
            'participant': self.participant.to_dict() if isinstance(self.participant, TLObject) else self.participant,
            'users': [] if self.users is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.users]
        }

    def __bytes__(self):
        return b''.join((
            b'c\xb1\xd9\xd0',
            bytes(self.participant),
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.users)),b''.join(bytes(x) for x in self.users),
        ))

    @classmethod
    def from_reader(cls, reader):
        _participant = reader.tgread_object()
        reader.read_int()
        _users = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _users.append(_x)

        return cls(participant=_participant, users=_users)


class ChannelParticipants(TLObject):
    CONSTRUCTOR_ID = 0xf56ee2a8
    SUBCLASS_OF_ID = 0xe60a6e64

    def __init__(self, count, participants, users):
        """
        :param int count:
        :param List[TypeChannelParticipant] participants:
        :param List[TypeUser] users:

        Constructor for channels.ChannelParticipants: Instance of either ChannelParticipants, ChannelParticipantsNotModified.
        """
        self.count = count  # type: int
        self.participants = participants  # type: List[TypeChannelParticipant]
        self.users = users  # type: List[TypeUser]

    def to_dict(self):
        return {
            '_': 'ChannelParticipants',
            'count': self.count,
            'participants': [] if self.participants is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.participants],
            'users': [] if self.users is None else [x.to_dict() if isinstance(x, TLObject) else x for x in self.users]
        }

    def __bytes__(self):
        return b''.join((
            b'\xa8\xe2n\xf5',
            struct.pack('<i', self.count),
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.participants)),b''.join(bytes(x) for x in self.participants),
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.users)),b''.join(bytes(x) for x in self.users),
        ))

    @classmethod
    def from_reader(cls, reader):
        _count = reader.read_int()
        reader.read_int()
        _participants = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _participants.append(_x)

        reader.read_int()
        _users = []
        for _ in range(reader.read_int()):
            _x = reader.tgread_object()
            _users.append(_x)

        return cls(count=_count, participants=_participants, users=_users)


class ChannelParticipantsNotModified(TLObject):
    CONSTRUCTOR_ID = 0xf0173fe9
    SUBCLASS_OF_ID = 0xe60a6e64

    def to_dict(self):
        return {
            '_': 'ChannelParticipantsNotModified'
        }

    def __bytes__(self):
        return b''.join((
            b'\xe9?\x17\xf0',
        ))

    @classmethod
    def from_reader(cls, reader):
        return cls()

