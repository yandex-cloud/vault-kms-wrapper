// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.0
// 	protoc        v3.17.3
// source: yandex/cloud/serverless/apigateway/websocket/v1/connection_service.proto

package websocket

import (
	_ "github.com/yandex-cloud/go-genproto/yandex/cloud"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SendToConnectionRequest_DataType int32

const (
	SendToConnectionRequest_DATA_TYPE_UNSPECIFIED SendToConnectionRequest_DataType = 0
	// Binary data.
	SendToConnectionRequest_BINARY SendToConnectionRequest_DataType = 1
	// Text data.
	SendToConnectionRequest_TEXT SendToConnectionRequest_DataType = 2
)

// Enum value maps for SendToConnectionRequest_DataType.
var (
	SendToConnectionRequest_DataType_name = map[int32]string{
		0: "DATA_TYPE_UNSPECIFIED",
		1: "BINARY",
		2: "TEXT",
	}
	SendToConnectionRequest_DataType_value = map[string]int32{
		"DATA_TYPE_UNSPECIFIED": 0,
		"BINARY":                1,
		"TEXT":                  2,
	}
)

func (x SendToConnectionRequest_DataType) Enum() *SendToConnectionRequest_DataType {
	p := new(SendToConnectionRequest_DataType)
	*p = x
	return p
}

func (x SendToConnectionRequest_DataType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SendToConnectionRequest_DataType) Descriptor() protoreflect.EnumDescriptor {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_enumTypes[0].Descriptor()
}

func (SendToConnectionRequest_DataType) Type() protoreflect.EnumType {
	return &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_enumTypes[0]
}

func (x SendToConnectionRequest_DataType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SendToConnectionRequest_DataType.Descriptor instead.
func (SendToConnectionRequest_DataType) EnumDescriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{1, 0}
}

type GetConnectionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the connection to get.
	ConnectionId string `protobuf:"bytes,1,opt,name=connection_id,json=connectionId,proto3" json:"connection_id,omitempty"`
}

func (x *GetConnectionRequest) Reset() {
	*x = GetConnectionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetConnectionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConnectionRequest) ProtoMessage() {}

func (x *GetConnectionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConnectionRequest.ProtoReflect.Descriptor instead.
func (*GetConnectionRequest) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetConnectionRequest) GetConnectionId() string {
	if x != nil {
		return x.ConnectionId
	}
	return ""
}

type SendToConnectionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the connection to which send.
	ConnectionId string `protobuf:"bytes,1,opt,name=connection_id,json=connectionId,proto3" json:"connection_id,omitempty"`
	// Data to send.
	Data []byte `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	// Type of the sending data.
	Type SendToConnectionRequest_DataType `protobuf:"varint,3,opt,name=type,proto3,enum=yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest_DataType" json:"type,omitempty"`
}

func (x *SendToConnectionRequest) Reset() {
	*x = SendToConnectionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendToConnectionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendToConnectionRequest) ProtoMessage() {}

func (x *SendToConnectionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendToConnectionRequest.ProtoReflect.Descriptor instead.
func (*SendToConnectionRequest) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{1}
}

func (x *SendToConnectionRequest) GetConnectionId() string {
	if x != nil {
		return x.ConnectionId
	}
	return ""
}

func (x *SendToConnectionRequest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *SendToConnectionRequest) GetType() SendToConnectionRequest_DataType {
	if x != nil {
		return x.Type
	}
	return SendToConnectionRequest_DATA_TYPE_UNSPECIFIED
}

type SendToConnectionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SendToConnectionResponse) Reset() {
	*x = SendToConnectionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendToConnectionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendToConnectionResponse) ProtoMessage() {}

func (x *SendToConnectionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendToConnectionResponse.ProtoReflect.Descriptor instead.
func (*SendToConnectionResponse) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{2}
}

type DisconnectRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the connection to disconnect.
	ConnectionId string `protobuf:"bytes,1,opt,name=connection_id,json=connectionId,proto3" json:"connection_id,omitempty"`
}

func (x *DisconnectRequest) Reset() {
	*x = DisconnectRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisconnectRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisconnectRequest) ProtoMessage() {}

func (x *DisconnectRequest) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisconnectRequest.ProtoReflect.Descriptor instead.
func (*DisconnectRequest) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{3}
}

func (x *DisconnectRequest) GetConnectionId() string {
	if x != nil {
		return x.ConnectionId
	}
	return ""
}

type DisconnectResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DisconnectResponse) Reset() {
	*x = DisconnectResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisconnectResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisconnectResponse) ProtoMessage() {}

func (x *DisconnectResponse) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisconnectResponse.ProtoReflect.Descriptor instead.
func (*DisconnectResponse) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP(), []int{4}
}

var File_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto protoreflect.FileDescriptor

var file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDesc = []byte{
	0x0a, 0x48, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74,
	0x65, 0x77, 0x61, 0x79, 0x2f, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x76,
	0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x2f, 0x79, 0x61, 0x6e, 0x64,
	0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c,
	0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x77,
	0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x79, 0x61, 0x6e, 0x64, 0x65,
	0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x40, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78,
	0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73,
	0x73, 0x2f, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2f, 0x77, 0x65, 0x62,
	0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x49, 0x0a, 0x14, 0x47, 0x65,
	0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x31, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0c, 0xe8, 0xc7, 0x31, 0x01, 0x8a,
	0xc8, 0x31, 0x04, 0x3c, 0x3d, 0x35, 0x30, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x64, 0x22, 0x96, 0x02, 0x0a, 0x17, 0x53, 0x65, 0x6e, 0x64, 0x54, 0x6f,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x31, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0c, 0xe8, 0xc7, 0x31, 0x01, 0x8a, 0xc8,
	0x31, 0x04, 0x3c, 0x3d, 0x35, 0x30, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x42, 0x10, 0xe8, 0xc7, 0x31, 0x01, 0x8a, 0xc8, 0x31, 0x08, 0x3c, 0x3d, 0x31, 0x33,
	0x31, 0x30, 0x37, 0x32, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x65, 0x0a, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x51, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65,
	0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65,
	0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x77, 0x65,
	0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x54,
	0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x22, 0x3b, 0x0a, 0x08, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a,
	0x15, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45,
	0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x42, 0x49, 0x4e, 0x41,
	0x52, 0x59, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x54, 0x45, 0x58, 0x54, 0x10, 0x02, 0x22, 0x1a,
	0x0a, 0x18, 0x53, 0x65, 0x6e, 0x64, 0x54, 0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x46, 0x0a, 0x11, 0x44, 0x69,
	0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x31, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0c, 0xe8, 0xc7, 0x31, 0x01, 0x8a, 0xc8, 0x31, 0x04,
	0x3c, 0x3d, 0x35, 0x30, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x49, 0x64, 0x22, 0x14, 0x0a, 0x12, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x9a, 0x05, 0x0a, 0x11, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0xc8,
	0x01, 0x0a, 0x03, 0x47, 0x65, 0x74, 0x12, 0x45, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e,
	0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73,
	0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x77, 0x65, 0x62, 0x73,
	0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x3b, 0x2e,
	0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77,
	0x61, 0x79, 0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x3d, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x37, 0x12, 0x35, 0x2f, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x73,
	0x2f, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x7b, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x7d, 0x12, 0xe2, 0x01, 0x0a, 0x04, 0x53, 0x65,
	0x6e, 0x64, 0x12, 0x48, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69,
	0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65,
	0x74, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x54, 0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x49, 0x2e, 0x79,
	0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61,
	0x79, 0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x53,
	0x65, 0x6e, 0x64, 0x54, 0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x45, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x3f, 0x3a,
	0x01, 0x2a, 0x22, 0x3a, 0x2f, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x73,
	0x2f, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x7b, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x7d, 0x3a, 0x73, 0x65, 0x6e, 0x64, 0x12, 0xd4,
	0x01, 0x0a, 0x0a, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x12, 0x42, 0x2e,
	0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77,
	0x61, 0x79, 0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x2e,
	0x44, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x43, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67,
	0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x3d, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x37, 0x2a, 0x35,
	0x2f, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x73, 0x2f, 0x77, 0x65, 0x62,
	0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x7b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x7d, 0x42, 0x94, 0x01, 0x0a, 0x33, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78,
	0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x6c, 0x65, 0x73, 0x73, 0x2e, 0x61, 0x70, 0x69, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79,
	0x2e, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x76, 0x31, 0x5a, 0x5d, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78,
	0x2d, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6c, 0x65, 0x73, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x67, 0x61,
	0x74, 0x65, 0x77, 0x61, 0x79, 0x2f, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x2f,
	0x76, 0x31, 0x3b, 0x77, 0x65, 0x62, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescOnce sync.Once
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescData = file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDesc
)

func file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescGZIP() []byte {
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescOnce.Do(func() {
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescData)
	})
	return file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDescData
}

var file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_goTypes = []interface{}{
	(SendToConnectionRequest_DataType)(0), // 0: yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest.DataType
	(*GetConnectionRequest)(nil),          // 1: yandex.cloud.serverless.apigateway.websocket.v1.GetConnectionRequest
	(*SendToConnectionRequest)(nil),       // 2: yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest
	(*SendToConnectionResponse)(nil),      // 3: yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionResponse
	(*DisconnectRequest)(nil),             // 4: yandex.cloud.serverless.apigateway.websocket.v1.DisconnectRequest
	(*DisconnectResponse)(nil),            // 5: yandex.cloud.serverless.apigateway.websocket.v1.DisconnectResponse
	(*Connection)(nil),                    // 6: yandex.cloud.serverless.apigateway.websocket.v1.Connection
}
var file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_depIdxs = []int32{
	0, // 0: yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest.type:type_name -> yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest.DataType
	1, // 1: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Get:input_type -> yandex.cloud.serverless.apigateway.websocket.v1.GetConnectionRequest
	2, // 2: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Send:input_type -> yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionRequest
	4, // 3: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Disconnect:input_type -> yandex.cloud.serverless.apigateway.websocket.v1.DisconnectRequest
	6, // 4: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Get:output_type -> yandex.cloud.serverless.apigateway.websocket.v1.Connection
	3, // 5: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Send:output_type -> yandex.cloud.serverless.apigateway.websocket.v1.SendToConnectionResponse
	5, // 6: yandex.cloud.serverless.apigateway.websocket.v1.ConnectionService.Disconnect:output_type -> yandex.cloud.serverless.apigateway.websocket.v1.DisconnectResponse
	4, // [4:7] is the sub-list for method output_type
	1, // [1:4] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_init() }
func file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_init() {
	if File_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto != nil {
		return
	}
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetConnectionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendToConnectionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendToConnectionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DisconnectRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DisconnectResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_goTypes,
		DependencyIndexes: file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_depIdxs,
		EnumInfos:         file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_enumTypes,
		MessageInfos:      file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_msgTypes,
	}.Build()
	File_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto = out.File
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_rawDesc = nil
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_goTypes = nil
	file_yandex_cloud_serverless_apigateway_websocket_v1_connection_service_proto_depIdxs = nil
}
