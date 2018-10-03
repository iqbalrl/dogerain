"""File generated by TLObjects' generator. All changes will be ERASED"""
from ...tl.tlobject import TLObject
from ...tl.tlobject import TLRequest
from typing import Optional, List, Union, TYPE_CHECKING
from . import auth, account, users, contacts, messages, updates, photos, upload, help, channels, bots, payments, stickers, phone, langpack
import os
import struct
if TYPE_CHECKING:
    from ...tl.types import TypeInputClientProxy, TypeType, TypeMessageRange, TypeX



class DestroySessionRequest(TLRequest):
    CONSTRUCTOR_ID = 0xe7512126
    SUBCLASS_OF_ID = 0xaf0ce7bd

    def __init__(self, session_id):
        """
        :param int session_id:

        :returns DestroySessionRes: Instance of either DestroySessionOk, DestroySessionNone.
        """
        self.session_id = session_id  # type: int

    def to_dict(self):
        return {
            '_': 'DestroySessionRequest',
            'session_id': self.session_id
        }

    def __bytes__(self):
        return b''.join((
            b'&!Q\xe7',
            struct.pack('<q', self.session_id),
        ))

    @classmethod
    def from_reader(cls, reader):
        _session_id = reader.read_long()
        return cls(session_id=_session_id)


class GetFutureSaltsRequest(TLRequest):
    CONSTRUCTOR_ID = 0xb921bd04
    SUBCLASS_OF_ID = 0x1090f517

    def __init__(self, num):
        """
        :param int num:

        :returns FutureSalts: Instance of FutureSalts.
        """
        self.num = num  # type: int

    def to_dict(self):
        return {
            '_': 'GetFutureSaltsRequest',
            'num': self.num
        }

    def __bytes__(self):
        return b''.join((
            b'\x04\xbd!\xb9',
            struct.pack('<i', self.num),
        ))

    @classmethod
    def from_reader(cls, reader):
        _num = reader.read_int()
        return cls(num=_num)


class HttpWaitRequest(TLRequest):
    CONSTRUCTOR_ID = 0x9299359f
    SUBCLASS_OF_ID = 0x1284aed6

    def __init__(self, max_delay, wait_after, max_wait):
        """
        :param int max_delay:
        :param int wait_after:
        :param int max_wait:

        :returns HttpWait: Instance of DummyHttpWait.
        """
        self.max_delay = max_delay  # type: int
        self.wait_after = wait_after  # type: int
        self.max_wait = max_wait  # type: int

    def to_dict(self):
        return {
            '_': 'HttpWaitRequest',
            'max_delay': self.max_delay,
            'wait_after': self.wait_after,
            'max_wait': self.max_wait
        }

    def __bytes__(self):
        return b''.join((
            b'\x9f5\x99\x92',
            struct.pack('<i', self.max_delay),
            struct.pack('<i', self.wait_after),
            struct.pack('<i', self.max_wait),
        ))

    @classmethod
    def from_reader(cls, reader):
        _max_delay = reader.read_int()
        _wait_after = reader.read_int()
        _max_wait = reader.read_int()
        return cls(max_delay=_max_delay, wait_after=_wait_after, max_wait=_max_wait)


class InitConnectionRequest(TLRequest):
    CONSTRUCTOR_ID = 0x785188b8
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, api_id, device_model, system_version, app_version, system_lang_code, lang_pack, lang_code, query, proxy=None):
        """
        :param int api_id:
        :param str device_model:
        :param str system_version:
        :param str app_version:
        :param str system_lang_code:
        :param str lang_pack:
        :param str lang_code:
        :param TypeX query:
        :param Optional[TypeInputClientProxy] proxy:

        :returns X: This type has no constructors.
        """
        self.api_id = api_id  # type: int
        self.device_model = device_model  # type: str
        self.system_version = system_version  # type: str
        self.app_version = app_version  # type: str
        self.system_lang_code = system_lang_code  # type: str
        self.lang_pack = lang_pack  # type: str
        self.lang_code = lang_code  # type: str
        self.query = query  # type: TypeX
        self.proxy = proxy  # type: Optional[TypeInputClientProxy]

    def to_dict(self):
        return {
            '_': 'InitConnectionRequest',
            'api_id': self.api_id,
            'device_model': self.device_model,
            'system_version': self.system_version,
            'app_version': self.app_version,
            'system_lang_code': self.system_lang_code,
            'lang_pack': self.lang_pack,
            'lang_code': self.lang_code,
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query,
            'proxy': self.proxy.to_dict() if isinstance(self.proxy, TLObject) else self.proxy
        }

    def __bytes__(self):
        return b''.join((
            b'\xb8\x88Qx',
            struct.pack('<I', (0 if self.proxy is None or self.proxy is False else 1)),
            struct.pack('<i', self.api_id),
            self.serialize_bytes(self.device_model),
            self.serialize_bytes(self.system_version),
            self.serialize_bytes(self.app_version),
            self.serialize_bytes(self.system_lang_code),
            self.serialize_bytes(self.lang_pack),
            self.serialize_bytes(self.lang_code),
            b'' if self.proxy is None or self.proxy is False else (bytes(self.proxy)),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        flags = reader.read_int()

        _api_id = reader.read_int()
        _device_model = reader.tgread_string()
        _system_version = reader.tgread_string()
        _app_version = reader.tgread_string()
        _system_lang_code = reader.tgread_string()
        _lang_pack = reader.tgread_string()
        _lang_code = reader.tgread_string()
        if flags & 1:
            _proxy = reader.tgread_object()
        else:
            _proxy = None
        _query = reader.tgread_object()
        return cls(api_id=_api_id, device_model=_device_model, system_version=_system_version, app_version=_app_version, system_lang_code=_system_lang_code, lang_pack=_lang_pack, lang_code=_lang_code, query=_query, proxy=_proxy)


class InvokeAfterMsgRequest(TLRequest):
    CONSTRUCTOR_ID = 0xcb9f372d
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, msg_id, query):
        """
        :param int msg_id:
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.msg_id = msg_id  # type: int
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeAfterMsgRequest',
            'msg_id': self.msg_id,
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'-7\x9f\xcb',
            struct.pack('<q', self.msg_id),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        _msg_id = reader.read_long()
        _query = reader.tgread_object()
        return cls(msg_id=_msg_id, query=_query)


class InvokeAfterMsgsRequest(TLRequest):
    CONSTRUCTOR_ID = 0x3dc4b4f0
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, msg_ids, query):
        """
        :param List[int] msg_ids:
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.msg_ids = msg_ids  # type: List[int]
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeAfterMsgsRequest',
            'msg_ids': [] if self.msg_ids is None else self.msg_ids[:],
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'\xf0\xb4\xc4=',
            b'\x15\xc4\xb5\x1c',struct.pack('<i', len(self.msg_ids)),b''.join(struct.pack('<q', x) for x in self.msg_ids),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        reader.read_int()
        _msg_ids = []
        for _ in range(reader.read_int()):
            _x = reader.read_long()
            _msg_ids.append(_x)

        _query = reader.tgread_object()
        return cls(msg_ids=_msg_ids, query=_query)


class InvokeWithLayerRequest(TLRequest):
    CONSTRUCTOR_ID = 0xda9b0d0d
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, layer, query):
        """
        :param int layer:
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.layer = layer  # type: int
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeWithLayerRequest',
            'layer': self.layer,
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'\r\r\x9b\xda',
            struct.pack('<i', self.layer),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        _layer = reader.read_int()
        _query = reader.tgread_object()
        return cls(layer=_layer, query=_query)


class InvokeWithMessagesRangeRequest(TLRequest):
    CONSTRUCTOR_ID = 0x365275f2
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, range, query):
        """
        :param TypeMessageRange range:
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.range = range  # type: TypeMessageRange
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeWithMessagesRangeRequest',
            'range': self.range.to_dict() if isinstance(self.range, TLObject) else self.range,
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'\xf2uR6',
            bytes(self.range),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        _range = reader.tgread_object()
        _query = reader.tgread_object()
        return cls(range=_range, query=_query)


class InvokeWithTakeoutRequest(TLRequest):
    CONSTRUCTOR_ID = 0xaca9fd2e
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, takeout_id, query):
        """
        :param int takeout_id:
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.takeout_id = takeout_id  # type: int
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeWithTakeoutRequest',
            'takeout_id': self.takeout_id,
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'.\xfd\xa9\xac',
            struct.pack('<q', self.takeout_id),
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        _takeout_id = reader.read_long()
        _query = reader.tgread_object()
        return cls(takeout_id=_takeout_id, query=_query)


class InvokeWithoutUpdatesRequest(TLRequest):
    CONSTRUCTOR_ID = 0xbf9459b7
    SUBCLASS_OF_ID = 0xb7b2364b

    def __init__(self, query):
        """
        :param TypeX query:

        :returns X: This type has no constructors.
        """
        self.query = query  # type: TypeX

    def to_dict(self):
        return {
            '_': 'InvokeWithoutUpdatesRequest',
            'query': self.query.to_dict() if isinstance(self.query, TLObject) else self.query
        }

    def __bytes__(self):
        return b''.join((
            b'\xb7Y\x94\xbf',
            bytes(self.query),
        ))

    @classmethod
    def from_reader(cls, reader):
        _query = reader.tgread_object()
        return cls(query=_query)


class PingRequest(TLRequest):
    CONSTRUCTOR_ID = 0x7abe77ec
    SUBCLASS_OF_ID = 0x816aee71

    def __init__(self, ping_id):
        """
        :param int ping_id:

        :returns Pong: Instance of Pong.
        """
        self.ping_id = ping_id  # type: int

    def to_dict(self):
        return {
            '_': 'PingRequest',
            'ping_id': self.ping_id
        }

    def __bytes__(self):
        return b''.join((
            b'\xecw\xbez',
            struct.pack('<q', self.ping_id),
        ))

    @classmethod
    def from_reader(cls, reader):
        _ping_id = reader.read_long()
        return cls(ping_id=_ping_id)


class PingDelayDisconnectRequest(TLRequest):
    CONSTRUCTOR_ID = 0xf3427b8c
    SUBCLASS_OF_ID = 0x816aee71

    def __init__(self, ping_id, disconnect_delay):
        """
        :param int ping_id:
        :param int disconnect_delay:

        :returns Pong: Instance of Pong.
        """
        self.ping_id = ping_id  # type: int
        self.disconnect_delay = disconnect_delay  # type: int

    def to_dict(self):
        return {
            '_': 'PingDelayDisconnectRequest',
            'ping_id': self.ping_id,
            'disconnect_delay': self.disconnect_delay
        }

    def __bytes__(self):
        return b''.join((
            b'\x8c{B\xf3',
            struct.pack('<q', self.ping_id),
            struct.pack('<i', self.disconnect_delay),
        ))

    @classmethod
    def from_reader(cls, reader):
        _ping_id = reader.read_long()
        _disconnect_delay = reader.read_int()
        return cls(ping_id=_ping_id, disconnect_delay=_disconnect_delay)


class ReqDHParamsRequest(TLRequest):
    CONSTRUCTOR_ID = 0xd712e4be
    SUBCLASS_OF_ID = 0xa6188d9e

    def __init__(self, nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data):
        """
        :param int nonce:
        :param int server_nonce:
        :param bytes p:
        :param bytes q:
        :param int public_key_fingerprint:
        :param str encrypted_data:

        :returns Server_DH_Params: Instance of either ServerDHParamsFail, ServerDHParamsOk.
        """
        self.nonce = nonce  # type: int
        self.server_nonce = server_nonce  # type: int
        self.p = p  # type: bytes
        self.q = q  # type: bytes
        self.public_key_fingerprint = public_key_fingerprint  # type: int
        self.encrypted_data = encrypted_data  # type: str

    def to_dict(self):
        return {
            '_': 'ReqDHParamsRequest',
            'nonce': self.nonce,
            'server_nonce': self.server_nonce,
            'p': self.p,
            'q': self.q,
            'public_key_fingerprint': self.public_key_fingerprint,
            'encrypted_data': self.encrypted_data
        }

    def __bytes__(self):
        return b''.join((
            b'\xbe\xe4\x12\xd7',
            self.nonce.to_bytes(16, 'little', signed=True),
            self.server_nonce.to_bytes(16, 'little', signed=True),
            self.serialize_bytes(self.p),
            self.serialize_bytes(self.q),
            struct.pack('<q', self.public_key_fingerprint),
            self.serialize_bytes(self.encrypted_data),
        ))

    @classmethod
    def from_reader(cls, reader):
        _nonce = reader.read_large_int(bits=128)
        _server_nonce = reader.read_large_int(bits=128)
        _p = reader.tgread_bytes()
        _q = reader.tgread_bytes()
        _public_key_fingerprint = reader.read_long()
        _encrypted_data = reader.tgread_string()
        return cls(nonce=_nonce, server_nonce=_server_nonce, p=_p, q=_q, public_key_fingerprint=_public_key_fingerprint, encrypted_data=_encrypted_data)


class ReqPqMultiRequest(TLRequest):
    CONSTRUCTOR_ID = 0xbe7e8ef1
    SUBCLASS_OF_ID = 0x786986b8

    def __init__(self, nonce):
        """
        :param int nonce:

        :returns ResPQ: Instance of ResPQ.
        """
        self.nonce = nonce  # type: int

    def to_dict(self):
        return {
            '_': 'ReqPqMultiRequest',
            'nonce': self.nonce
        }

    def __bytes__(self):
        return b''.join((
            b'\xf1\x8e~\xbe',
            self.nonce.to_bytes(16, 'little', signed=True),
        ))

    @classmethod
    def from_reader(cls, reader):
        _nonce = reader.read_large_int(bits=128)
        return cls(nonce=_nonce)


class RpcDropAnswerRequest(TLRequest):
    CONSTRUCTOR_ID = 0x58e4a740
    SUBCLASS_OF_ID = 0x4bca7570

    def __init__(self, req_msg_id):
        """
        :param int req_msg_id:

        :returns RpcDropAnswer: Instance of either RpcAnswerUnknown, RpcAnswerDroppedRunning, RpcAnswerDropped.
        """
        self.req_msg_id = req_msg_id  # type: int

    def to_dict(self):
        return {
            '_': 'RpcDropAnswerRequest',
            'req_msg_id': self.req_msg_id
        }

    def __bytes__(self):
        return b''.join((
            b'@\xa7\xe4X',
            struct.pack('<q', self.req_msg_id),
        ))

    @classmethod
    def from_reader(cls, reader):
        _req_msg_id = reader.read_long()
        return cls(req_msg_id=_req_msg_id)


class SetClientDHParamsRequest(TLRequest):
    CONSTRUCTOR_ID = 0xf5045f1f
    SUBCLASS_OF_ID = 0x55dd6cdb

    def __init__(self, nonce, server_nonce, encrypted_data):
        """
        :param int nonce:
        :param int server_nonce:
        :param bytes encrypted_data:

        :returns Set_client_DH_params_answer: Instance of either DhGenOk, DhGenRetry, DhGenFail.
        """
        self.nonce = nonce  # type: int
        self.server_nonce = server_nonce  # type: int
        self.encrypted_data = encrypted_data  # type: bytes

    def to_dict(self):
        return {
            '_': 'SetClientDHParamsRequest',
            'nonce': self.nonce,
            'server_nonce': self.server_nonce,
            'encrypted_data': self.encrypted_data
        }

    def __bytes__(self):
        return b''.join((
            b'\x1f_\x04\xf5',
            self.nonce.to_bytes(16, 'little', signed=True),
            self.server_nonce.to_bytes(16, 'little', signed=True),
            self.serialize_bytes(self.encrypted_data),
        ))

    @classmethod
    def from_reader(cls, reader):
        _nonce = reader.read_large_int(bits=128)
        _server_nonce = reader.read_large_int(bits=128)
        _encrypted_data = reader.tgread_bytes()
        return cls(nonce=_nonce, server_nonce=_server_nonce, encrypted_data=_encrypted_data)

