// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.0
// 	protoc        v3.17.3
// source: yandex/cloud/compute/v1/host_group.proto

package compute

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type MaintenancePolicy int32

const (
	MaintenancePolicy_MAINTENANCE_POLICY_UNSPECIFIED MaintenancePolicy = 0
	// Restart instances on the same host after maintenance event.
	MaintenancePolicy_RESTART MaintenancePolicy = 1
	// Migrate instances to another host before maintenance event.
	MaintenancePolicy_MIGRATE MaintenancePolicy = 2
)

// Enum value maps for MaintenancePolicy.
var (
	MaintenancePolicy_name = map[int32]string{
		0: "MAINTENANCE_POLICY_UNSPECIFIED",
		1: "RESTART",
		2: "MIGRATE",
	}
	MaintenancePolicy_value = map[string]int32{
		"MAINTENANCE_POLICY_UNSPECIFIED": 0,
		"RESTART":                        1,
		"MIGRATE":                        2,
	}
)

func (x MaintenancePolicy) Enum() *MaintenancePolicy {
	p := new(MaintenancePolicy)
	*p = x
	return p
}

func (x MaintenancePolicy) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MaintenancePolicy) Descriptor() protoreflect.EnumDescriptor {
	return file_yandex_cloud_compute_v1_host_group_proto_enumTypes[0].Descriptor()
}

func (MaintenancePolicy) Type() protoreflect.EnumType {
	return &file_yandex_cloud_compute_v1_host_group_proto_enumTypes[0]
}

func (x MaintenancePolicy) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MaintenancePolicy.Descriptor instead.
func (MaintenancePolicy) EnumDescriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{0}
}

type HostGroup_Status int32

const (
	HostGroup_STATUS_UNSPECIFIED HostGroup_Status = 0
	HostGroup_CREATING           HostGroup_Status = 1
	HostGroup_READY              HostGroup_Status = 2
	HostGroup_UPDATING           HostGroup_Status = 3
	HostGroup_DELETING           HostGroup_Status = 4
)

// Enum value maps for HostGroup_Status.
var (
	HostGroup_Status_name = map[int32]string{
		0: "STATUS_UNSPECIFIED",
		1: "CREATING",
		2: "READY",
		3: "UPDATING",
		4: "DELETING",
	}
	HostGroup_Status_value = map[string]int32{
		"STATUS_UNSPECIFIED": 0,
		"CREATING":           1,
		"READY":              2,
		"UPDATING":           3,
		"DELETING":           4,
	}
)

func (x HostGroup_Status) Enum() *HostGroup_Status {
	p := new(HostGroup_Status)
	*p = x
	return p
}

func (x HostGroup_Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HostGroup_Status) Descriptor() protoreflect.EnumDescriptor {
	return file_yandex_cloud_compute_v1_host_group_proto_enumTypes[1].Descriptor()
}

func (HostGroup_Status) Type() protoreflect.EnumType {
	return &file_yandex_cloud_compute_v1_host_group_proto_enumTypes[1]
}

func (x HostGroup_Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HostGroup_Status.Descriptor instead.
func (HostGroup_Status) EnumDescriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{0, 0}
}

type Host_Status int32

const (
	Host_STATUS_UNSPECIFIED Host_Status = 0
	Host_UP                 Host_Status = 1
	Host_DOWN               Host_Status = 2
)

// Enum value maps for Host_Status.
var (
	Host_Status_name = map[int32]string{
		0: "STATUS_UNSPECIFIED",
		1: "UP",
		2: "DOWN",
	}
	Host_Status_value = map[string]int32{
		"STATUS_UNSPECIFIED": 0,
		"UP":                 1,
		"DOWN":               2,
	}
)

func (x Host_Status) Enum() *Host_Status {
	p := new(Host_Status)
	*p = x
	return p
}

func (x Host_Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Host_Status) Descriptor() protoreflect.EnumDescriptor {
	return file_yandex_cloud_compute_v1_host_group_proto_enumTypes[2].Descriptor()
}

func (Host_Status) Type() protoreflect.EnumType {
	return &file_yandex_cloud_compute_v1_host_group_proto_enumTypes[2]
}

func (x Host_Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Host_Status.Descriptor instead.
func (Host_Status) EnumDescriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{1, 0}
}

// Represents group of dedicated hosts
type HostGroup struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the group.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// ID of the folder that the group belongs to.
	FolderId string `protobuf:"bytes,2,opt,name=folder_id,json=folderId,proto3" json:"folder_id,omitempty"`
	// Creation timestamp in [RFC3339](https://www.ietf.org/rfc/rfc3339.txt) text format.
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	// Name of the group. The name is unique within the folder.
	Name string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// Description of the group.
	Description string `protobuf:"bytes,5,opt,name=description,proto3" json:"description,omitempty"`
	// Resource labels as `key:value` pairs.
	Labels map[string]string `protobuf:"bytes,6,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Availability zone where all dedicated hosts are allocated.
	ZoneId string `protobuf:"bytes,7,opt,name=zone_id,json=zoneId,proto3" json:"zone_id,omitempty"`
	// Status of the group.
	Status HostGroup_Status `protobuf:"varint,8,opt,name=status,proto3,enum=yandex.cloud.compute.v1.HostGroup_Status" json:"status,omitempty"`
	// ID of host type. Resources provided by each host of the group.
	TypeId string `protobuf:"bytes,9,opt,name=type_id,json=typeId,proto3" json:"type_id,omitempty"`
	// Behaviour on maintenance events.
	MaintenancePolicy MaintenancePolicy `protobuf:"varint,10,opt,name=maintenance_policy,json=maintenancePolicy,proto3,enum=yandex.cloud.compute.v1.MaintenancePolicy" json:"maintenance_policy,omitempty"`
	// Scale policy. Only fixed number of hosts are supported at this moment.
	ScalePolicy *ScalePolicy `protobuf:"bytes,11,opt,name=scale_policy,json=scalePolicy,proto3" json:"scale_policy,omitempty"`
}

func (x *HostGroup) Reset() {
	*x = HostGroup{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HostGroup) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HostGroup) ProtoMessage() {}

func (x *HostGroup) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HostGroup.ProtoReflect.Descriptor instead.
func (*HostGroup) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{0}
}

func (x *HostGroup) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HostGroup) GetFolderId() string {
	if x != nil {
		return x.FolderId
	}
	return ""
}

func (x *HostGroup) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *HostGroup) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *HostGroup) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *HostGroup) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *HostGroup) GetZoneId() string {
	if x != nil {
		return x.ZoneId
	}
	return ""
}

func (x *HostGroup) GetStatus() HostGroup_Status {
	if x != nil {
		return x.Status
	}
	return HostGroup_STATUS_UNSPECIFIED
}

func (x *HostGroup) GetTypeId() string {
	if x != nil {
		return x.TypeId
	}
	return ""
}

func (x *HostGroup) GetMaintenancePolicy() MaintenancePolicy {
	if x != nil {
		return x.MaintenancePolicy
	}
	return MaintenancePolicy_MAINTENANCE_POLICY_UNSPECIFIED
}

func (x *HostGroup) GetScalePolicy() *ScalePolicy {
	if x != nil {
		return x.ScalePolicy
	}
	return nil
}

// Represents a dedicated host
type Host struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the host.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Current status of the host. New instances are unable to start on host in DOWN status.
	Status Host_Status `protobuf:"varint,2,opt,name=status,proto3,enum=yandex.cloud.compute.v1.Host_Status" json:"status,omitempty"`
	// ID of the physical server that the host belongs to.
	ServerId string `protobuf:"bytes,3,opt,name=server_id,json=serverId,proto3" json:"server_id,omitempty"`
}

func (x *Host) Reset() {
	*x = Host{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Host) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Host) ProtoMessage() {}

func (x *Host) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Host.ProtoReflect.Descriptor instead.
func (*Host) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{1}
}

func (x *Host) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Host) GetStatus() Host_Status {
	if x != nil {
		return x.Status
	}
	return Host_STATUS_UNSPECIFIED
}

func (x *Host) GetServerId() string {
	if x != nil {
		return x.ServerId
	}
	return ""
}

type ScalePolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to ScaleType:
	//
	//	*ScalePolicy_FixedScale_
	ScaleType isScalePolicy_ScaleType `protobuf_oneof:"scale_type"`
}

func (x *ScalePolicy) Reset() {
	*x = ScalePolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScalePolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScalePolicy) ProtoMessage() {}

func (x *ScalePolicy) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScalePolicy.ProtoReflect.Descriptor instead.
func (*ScalePolicy) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{2}
}

func (m *ScalePolicy) GetScaleType() isScalePolicy_ScaleType {
	if m != nil {
		return m.ScaleType
	}
	return nil
}

func (x *ScalePolicy) GetFixedScale() *ScalePolicy_FixedScale {
	if x, ok := x.GetScaleType().(*ScalePolicy_FixedScale_); ok {
		return x.FixedScale
	}
	return nil
}

type isScalePolicy_ScaleType interface {
	isScalePolicy_ScaleType()
}

type ScalePolicy_FixedScale_ struct {
	FixedScale *ScalePolicy_FixedScale `protobuf:"bytes,1,opt,name=fixed_scale,json=fixedScale,proto3,oneof"`
}

func (*ScalePolicy_FixedScale_) isScalePolicy_ScaleType() {}

type ScalePolicy_FixedScale struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Size int64 `protobuf:"varint,1,opt,name=size,proto3" json:"size,omitempty"`
}

func (x *ScalePolicy_FixedScale) Reset() {
	*x = ScalePolicy_FixedScale{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScalePolicy_FixedScale) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScalePolicy_FixedScale) ProtoMessage() {}

func (x *ScalePolicy_FixedScale) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_host_group_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScalePolicy_FixedScale.ProtoReflect.Descriptor instead.
func (*ScalePolicy_FixedScale) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP(), []int{2, 0}
}

func (x *ScalePolicy_FixedScale) GetSize() int64 {
	if x != nil {
		return x.Size
	}
	return 0
}

var File_yandex_cloud_compute_v1_host_group_proto protoreflect.FileDescriptor

var file_yandex_cloud_compute_v1_host_group_proto_rawDesc = []byte{
	0x0a, 0x28, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x63,
	0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x68, 0x6f, 0x73, 0x74, 0x5f, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x17, 0x79, 0x61, 0x6e, 0x64,
	0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65,
	0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9c, 0x05, 0x0a, 0x09, 0x48, 0x6f, 0x73, 0x74, 0x47, 0x72, 0x6f,
	0x75, 0x70, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20,
	0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x46, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x2e, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x47,
	0x72, 0x6f, 0x75, 0x70, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x12, 0x17, 0x0a, 0x07, 0x7a, 0x6f, 0x6e, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x7a, 0x6f, 0x6e, 0x65, 0x49,
	0x64, 0x12, 0x41, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x29, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x17, 0x0a, 0x07, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x79, 0x70, 0x65, 0x49, 0x64, 0x12, 0x59, 0x0a,
	0x12, 0x6d, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2a, 0x2e, 0x79, 0x61, 0x6e, 0x64,
	0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x11, 0x6d, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x61, 0x6e,
	0x63, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x47, 0x0a, 0x0c, 0x73, 0x63, 0x61, 0x6c,
	0x65, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24,
	0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f,
	0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x61, 0x6c, 0x65, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x52, 0x0b, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x55, 0x0a, 0x06,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x16, 0x0a, 0x12, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53,
	0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0c,
	0x0a, 0x08, 0x43, 0x52, 0x45, 0x41, 0x54, 0x49, 0x4e, 0x47, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05,
	0x52, 0x45, 0x41, 0x44, 0x59, 0x10, 0x02, 0x12, 0x0c, 0x0a, 0x08, 0x55, 0x50, 0x44, 0x41, 0x54,
	0x49, 0x4e, 0x47, 0x10, 0x03, 0x12, 0x0c, 0x0a, 0x08, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x49, 0x4e,
	0x47, 0x10, 0x04, 0x22, 0xa5, 0x01, 0x0a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x3c, 0x0a, 0x06,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x24, 0x2e, 0x79,
	0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70,
	0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x49, 0x64, 0x22, 0x32, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x12, 0x16, 0x0a, 0x12, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x55, 0x50, 0x10,
	0x01, 0x12, 0x08, 0x0a, 0x04, 0x44, 0x4f, 0x57, 0x4e, 0x10, 0x02, 0x22, 0x91, 0x01, 0x0a, 0x0b,
	0x53, 0x63, 0x61, 0x6c, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x52, 0x0a, 0x0b, 0x66,
	0x69, 0x78, 0x65, 0x64, 0x5f, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2f, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x61, 0x6c, 0x65,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x46, 0x69, 0x78, 0x65, 0x64, 0x53, 0x63, 0x61, 0x6c,
	0x65, 0x48, 0x00, 0x52, 0x0a, 0x66, 0x69, 0x78, 0x65, 0x64, 0x53, 0x63, 0x61, 0x6c, 0x65, 0x1a,
	0x20, 0x0a, 0x0a, 0x46, 0x69, 0x78, 0x65, 0x64, 0x53, 0x63, 0x61, 0x6c, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x73, 0x69, 0x7a,
	0x65, 0x42, 0x0c, 0x0a, 0x0a, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x2a,
	0x51, 0x0a, 0x11, 0x4d, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x63, 0x65, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x12, 0x22, 0x0a, 0x1e, 0x4d, 0x41, 0x49, 0x4e, 0x54, 0x45, 0x4e, 0x41,
	0x4e, 0x43, 0x45, 0x5f, 0x50, 0x4f, 0x4c, 0x49, 0x43, 0x59, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45,
	0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x52, 0x45, 0x53, 0x54,
	0x41, 0x52, 0x54, 0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x4d, 0x49, 0x47, 0x52, 0x41, 0x54, 0x45,
	0x10, 0x02, 0x42, 0x62, 0x0a, 0x1b, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76,
	0x31, 0x5a, 0x43, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x79, 0x61,
	0x6e, 0x64, 0x65, 0x78, 0x2d, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65,
	0x6e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c,
	0x6f, 0x75, 0x64, 0x2f, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x63,
	0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_yandex_cloud_compute_v1_host_group_proto_rawDescOnce sync.Once
	file_yandex_cloud_compute_v1_host_group_proto_rawDescData = file_yandex_cloud_compute_v1_host_group_proto_rawDesc
)

func file_yandex_cloud_compute_v1_host_group_proto_rawDescGZIP() []byte {
	file_yandex_cloud_compute_v1_host_group_proto_rawDescOnce.Do(func() {
		file_yandex_cloud_compute_v1_host_group_proto_rawDescData = protoimpl.X.CompressGZIP(file_yandex_cloud_compute_v1_host_group_proto_rawDescData)
	})
	return file_yandex_cloud_compute_v1_host_group_proto_rawDescData
}

var file_yandex_cloud_compute_v1_host_group_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_yandex_cloud_compute_v1_host_group_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_yandex_cloud_compute_v1_host_group_proto_goTypes = []interface{}{
	(MaintenancePolicy)(0),         // 0: yandex.cloud.compute.v1.MaintenancePolicy
	(HostGroup_Status)(0),          // 1: yandex.cloud.compute.v1.HostGroup.Status
	(Host_Status)(0),               // 2: yandex.cloud.compute.v1.Host.Status
	(*HostGroup)(nil),              // 3: yandex.cloud.compute.v1.HostGroup
	(*Host)(nil),                   // 4: yandex.cloud.compute.v1.Host
	(*ScalePolicy)(nil),            // 5: yandex.cloud.compute.v1.ScalePolicy
	nil,                            // 6: yandex.cloud.compute.v1.HostGroup.LabelsEntry
	(*ScalePolicy_FixedScale)(nil), // 7: yandex.cloud.compute.v1.ScalePolicy.FixedScale
	(*timestamppb.Timestamp)(nil),  // 8: google.protobuf.Timestamp
}
var file_yandex_cloud_compute_v1_host_group_proto_depIdxs = []int32{
	8, // 0: yandex.cloud.compute.v1.HostGroup.created_at:type_name -> google.protobuf.Timestamp
	6, // 1: yandex.cloud.compute.v1.HostGroup.labels:type_name -> yandex.cloud.compute.v1.HostGroup.LabelsEntry
	1, // 2: yandex.cloud.compute.v1.HostGroup.status:type_name -> yandex.cloud.compute.v1.HostGroup.Status
	0, // 3: yandex.cloud.compute.v1.HostGroup.maintenance_policy:type_name -> yandex.cloud.compute.v1.MaintenancePolicy
	5, // 4: yandex.cloud.compute.v1.HostGroup.scale_policy:type_name -> yandex.cloud.compute.v1.ScalePolicy
	2, // 5: yandex.cloud.compute.v1.Host.status:type_name -> yandex.cloud.compute.v1.Host.Status
	7, // 6: yandex.cloud.compute.v1.ScalePolicy.fixed_scale:type_name -> yandex.cloud.compute.v1.ScalePolicy.FixedScale
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_yandex_cloud_compute_v1_host_group_proto_init() }
func file_yandex_cloud_compute_v1_host_group_proto_init() {
	if File_yandex_cloud_compute_v1_host_group_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_yandex_cloud_compute_v1_host_group_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HostGroup); i {
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
		file_yandex_cloud_compute_v1_host_group_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Host); i {
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
		file_yandex_cloud_compute_v1_host_group_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScalePolicy); i {
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
		file_yandex_cloud_compute_v1_host_group_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScalePolicy_FixedScale); i {
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
	file_yandex_cloud_compute_v1_host_group_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*ScalePolicy_FixedScale_)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_yandex_cloud_compute_v1_host_group_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_yandex_cloud_compute_v1_host_group_proto_goTypes,
		DependencyIndexes: file_yandex_cloud_compute_v1_host_group_proto_depIdxs,
		EnumInfos:         file_yandex_cloud_compute_v1_host_group_proto_enumTypes,
		MessageInfos:      file_yandex_cloud_compute_v1_host_group_proto_msgTypes,
	}.Build()
	File_yandex_cloud_compute_v1_host_group_proto = out.File
	file_yandex_cloud_compute_v1_host_group_proto_rawDesc = nil
	file_yandex_cloud_compute_v1_host_group_proto_goTypes = nil
	file_yandex_cloud_compute_v1_host_group_proto_depIdxs = nil
}
