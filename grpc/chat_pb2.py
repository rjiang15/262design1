# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: chat.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'chat.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\nchat.proto\x12\x04\x63hat\x1a\x1bgoogle/protobuf/empty.proto\"\x1f\n\x0eShowDBResponse\x12\r\n\x05lines\x18\x01 \x03(\t\"=\n\x0bListRequest\x12\x0f\n\x07pattern\x18\x01 \x01(\t\x12\x0e\n\x06offset\x18\x02 \x01(\x05\x12\r\n\x05limit\x18\x03 \x01(\x05\"V\n\x0cListResponse\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x13\n\x0btotal_count\x18\x03 \x01(\x05\x12\x10\n\x08\x61\x63\x63ounts\x18\x04 \x03(\t\"\\\n\x10ReadConvoRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\x12\n\nother_user\x18\x03 \x01(\t\x12\t\n\x01n\x18\x04 \x01(\x05\"U\n\x11ReadConvoResponse\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x1f\n\x08messages\x18\x03 \x03(\x0b\x32\r.chat.Message\"Q\n\x10PollConvoRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\x12\n\nother_user\x18\x03 \x01(\t\"U\n\x11PollConvoResponse\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x1f\n\x08messages\x18\x03 \x03(\x0b\x32\r.chat.Message\"H\n\x10ReadInboxRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\t\n\x01n\x18\x03 \x01(\x05\"U\n\x11ReadInboxResponse\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x1f\n\x08messages\x18\x03 \x03(\x0b\x32\r.chat.Message\";\n\x0e\x41\x63\x63ountRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\"a\n\x12SendMessageRequest\x12\x0e\n\x06sender\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\x11\n\trecipient\x18\x03 \x01(\t\x12\x0f\n\x07message\x18\x04 \x01(\t\"V\n\x14\x44\x65leteMessageRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\x13\n\x0bmessage_ids\x18\x03 \x01(\t\"P\n\x0fMarkReadRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\x12\x12\n\nmessage_id\x18\x03 \x01(\t\"E\n\x18ListConversationsRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\"\\\n\x19ListConversationsResponse\x12\x14\n\x0ctotal_unread\x18\x01 \x01(\x05\x12)\n\rconversations\x18\x02 \x03(\x0b\x32\x12.chat.Conversation\"E\n\x0c\x43onversation\x12\x0f\n\x07partner\x18\x01 \x01(\t\x12\x0e\n\x06unread\x18\x02 \x01(\x05\x12\x14\n\x0clast_message\x18\x03 \x01(\t\"+\n\x08Response\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x0f\n\x07message\x18\x02 \x01(\t\"6\n\x07Message\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0e\n\x06sender\x18\x02 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x03 \x01(\t2\xbc\x06\n\x0b\x43hatService\x12\x36\n\x06ShowDB\x12\x16.google.protobuf.Empty\x1a\x14.chat.ShowDBResponse\x12-\n\x04List\x12\x11.chat.ListRequest\x1a\x12.chat.ListResponse\x12T\n\x11ListConversations\x12\x1e.chat.ListConversationsRequest\x1a\x1f.chat.ListConversationsResponse\x12<\n\tReadInbox\x12\x16.chat.ReadInboxRequest\x1a\x17.chat.ReadInboxResponse\x12<\n\tReadConvo\x12\x16.chat.ReadConvoRequest\x1a\x17.chat.ReadConvoResponse\x12@\n\rReadFullConvo\x12\x16.chat.ReadConvoRequest\x1a\x17.chat.ReadConvoResponse\x12<\n\tPollConvo\x12\x16.chat.PollConvoRequest\x1a\x17.chat.PollConvoResponse\x12\x35\n\rCreateAccount\x12\x14.chat.AccountRequest\x1a\x0e.chat.Response\x12-\n\x05Login\x12\x14.chat.AccountRequest\x1a\x0e.chat.Response\x12.\n\x06Logout\x12\x14.chat.AccountRequest\x1a\x0e.chat.Response\x12\x35\n\rDeleteAccount\x12\x14.chat.AccountRequest\x1a\x0e.chat.Response\x12\x37\n\x0bSendMessage\x12\x18.chat.SendMessageRequest\x1a\x0e.chat.Response\x12;\n\rDeleteMessage\x12\x1a.chat.DeleteMessageRequest\x1a\x0e.chat.Response\x12\x31\n\x08MarkRead\x12\x15.chat.MarkReadRequest\x1a\x0e.chat.Responseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'chat_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_SHOWDBRESPONSE']._serialized_start=49
  _globals['_SHOWDBRESPONSE']._serialized_end=80
  _globals['_LISTREQUEST']._serialized_start=82
  _globals['_LISTREQUEST']._serialized_end=143
  _globals['_LISTRESPONSE']._serialized_start=145
  _globals['_LISTRESPONSE']._serialized_end=231
  _globals['_READCONVOREQUEST']._serialized_start=233
  _globals['_READCONVOREQUEST']._serialized_end=325
  _globals['_READCONVORESPONSE']._serialized_start=327
  _globals['_READCONVORESPONSE']._serialized_end=412
  _globals['_POLLCONVOREQUEST']._serialized_start=414
  _globals['_POLLCONVOREQUEST']._serialized_end=495
  _globals['_POLLCONVORESPONSE']._serialized_start=497
  _globals['_POLLCONVORESPONSE']._serialized_end=582
  _globals['_READINBOXREQUEST']._serialized_start=584
  _globals['_READINBOXREQUEST']._serialized_end=656
  _globals['_READINBOXRESPONSE']._serialized_start=658
  _globals['_READINBOXRESPONSE']._serialized_end=743
  _globals['_ACCOUNTREQUEST']._serialized_start=745
  _globals['_ACCOUNTREQUEST']._serialized_end=804
  _globals['_SENDMESSAGEREQUEST']._serialized_start=806
  _globals['_SENDMESSAGEREQUEST']._serialized_end=903
  _globals['_DELETEMESSAGEREQUEST']._serialized_start=905
  _globals['_DELETEMESSAGEREQUEST']._serialized_end=991
  _globals['_MARKREADREQUEST']._serialized_start=993
  _globals['_MARKREADREQUEST']._serialized_end=1073
  _globals['_LISTCONVERSATIONSREQUEST']._serialized_start=1075
  _globals['_LISTCONVERSATIONSREQUEST']._serialized_end=1144
  _globals['_LISTCONVERSATIONSRESPONSE']._serialized_start=1146
  _globals['_LISTCONVERSATIONSRESPONSE']._serialized_end=1238
  _globals['_CONVERSATION']._serialized_start=1240
  _globals['_CONVERSATION']._serialized_end=1309
  _globals['_RESPONSE']._serialized_start=1311
  _globals['_RESPONSE']._serialized_end=1354
  _globals['_MESSAGE']._serialized_start=1356
  _globals['_MESSAGE']._serialized_end=1410
  _globals['_CHATSERVICE']._serialized_start=1413
  _globals['_CHATSERVICE']._serialized_end=2241
# @@protoc_insertion_point(module_scope)
