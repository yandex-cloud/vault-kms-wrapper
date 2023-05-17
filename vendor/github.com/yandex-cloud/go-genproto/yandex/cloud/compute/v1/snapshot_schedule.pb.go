// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.29.0
// 	protoc        v3.17.3
// source: yandex/cloud/compute/v1/snapshot_schedule.proto

package compute

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
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

type SnapshotSchedule_Status int32

const (
	SnapshotSchedule_STATUS_UNSPECIFIED SnapshotSchedule_Status = 0
	// The snapshot schedule is being created.
	SnapshotSchedule_CREATING SnapshotSchedule_Status = 1
	// The snapshot schedule is on: new disk snapshots will be created, old ones deleted
	// (if [SnapshotSchedule.retention_policy] is specified).
	SnapshotSchedule_ACTIVE SnapshotSchedule_Status = 2
	// The schedule is interrupted, snapshots won't be created or deleted.
	SnapshotSchedule_INACTIVE SnapshotSchedule_Status = 3
	// The schedule is being deleted.
	SnapshotSchedule_DELETING SnapshotSchedule_Status = 4
	// Changes are being made to snapshot schedule settings or a list of attached disks.
	SnapshotSchedule_UPDATING SnapshotSchedule_Status = 5
)

// Enum value maps for SnapshotSchedule_Status.
var (
	SnapshotSchedule_Status_name = map[int32]string{
		0: "STATUS_UNSPECIFIED",
		1: "CREATING",
		2: "ACTIVE",
		3: "INACTIVE",
		4: "DELETING",
		5: "UPDATING",
	}
	SnapshotSchedule_Status_value = map[string]int32{
		"STATUS_UNSPECIFIED": 0,
		"CREATING":           1,
		"ACTIVE":             2,
		"INACTIVE":           3,
		"DELETING":           4,
		"UPDATING":           5,
	}
)

func (x SnapshotSchedule_Status) Enum() *SnapshotSchedule_Status {
	p := new(SnapshotSchedule_Status)
	*p = x
	return p
}

func (x SnapshotSchedule_Status) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SnapshotSchedule_Status) Descriptor() protoreflect.EnumDescriptor {
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_enumTypes[0].Descriptor()
}

func (SnapshotSchedule_Status) Type() protoreflect.EnumType {
	return &file_yandex_cloud_compute_v1_snapshot_schedule_proto_enumTypes[0]
}

func (x SnapshotSchedule_Status) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SnapshotSchedule_Status.Descriptor instead.
func (SnapshotSchedule_Status) EnumDescriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescGZIP(), []int{0, 0}
}

// A snapshot schedule. For details about the concept, see [documentation](/docs/compute/concepts/snapshot-schedule).
type SnapshotSchedule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// ID of the snapshot schedule.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// ID of the folder that the snapshot schedule belongs to.
	FolderId string `protobuf:"bytes,2,opt,name=folder_id,json=folderId,proto3" json:"folder_id,omitempty"`
	// Creation timestamp.
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	// Name of the snapshot schedule.
	//
	// The name is unique within the folder.
	Name string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	// Description of the snapshot schedule.
	Description string `protobuf:"bytes,5,opt,name=description,proto3" json:"description,omitempty"`
	// Snapshot schedule labels as `key:value` pairs.
	Labels map[string]string `protobuf:"bytes,6,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Status of the snapshot schedule.
	Status SnapshotSchedule_Status `protobuf:"varint,7,opt,name=status,proto3,enum=yandex.cloud.compute.v1.SnapshotSchedule_Status" json:"status,omitempty"`
	// Frequency settings of the snapshot schedule.
	SchedulePolicy *SchedulePolicy `protobuf:"bytes,8,opt,name=schedule_policy,json=schedulePolicy,proto3" json:"schedule_policy,omitempty"`
	// Retention policy of the snapshot schedule.
	//
	// Types that are assignable to RetentionPolicy:
	//
	//	*SnapshotSchedule_RetentionPeriod
	//	*SnapshotSchedule_SnapshotCount
	RetentionPolicy isSnapshotSchedule_RetentionPolicy `protobuf_oneof:"retention_policy"`
	// Attributes of snapshots created by the snapshot schedule.
	SnapshotSpec *SnapshotSpec `protobuf:"bytes,11,opt,name=snapshot_spec,json=snapshotSpec,proto3" json:"snapshot_spec,omitempty"`
}

func (x *SnapshotSchedule) Reset() {
	*x = SnapshotSchedule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotSchedule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotSchedule) ProtoMessage() {}

func (x *SnapshotSchedule) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotSchedule.ProtoReflect.Descriptor instead.
func (*SnapshotSchedule) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescGZIP(), []int{0}
}

func (x *SnapshotSchedule) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *SnapshotSchedule) GetFolderId() string {
	if x != nil {
		return x.FolderId
	}
	return ""
}

func (x *SnapshotSchedule) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *SnapshotSchedule) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SnapshotSchedule) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *SnapshotSchedule) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

func (x *SnapshotSchedule) GetStatus() SnapshotSchedule_Status {
	if x != nil {
		return x.Status
	}
	return SnapshotSchedule_STATUS_UNSPECIFIED
}

func (x *SnapshotSchedule) GetSchedulePolicy() *SchedulePolicy {
	if x != nil {
		return x.SchedulePolicy
	}
	return nil
}

func (m *SnapshotSchedule) GetRetentionPolicy() isSnapshotSchedule_RetentionPolicy {
	if m != nil {
		return m.RetentionPolicy
	}
	return nil
}

func (x *SnapshotSchedule) GetRetentionPeriod() *durationpb.Duration {
	if x, ok := x.GetRetentionPolicy().(*SnapshotSchedule_RetentionPeriod); ok {
		return x.RetentionPeriod
	}
	return nil
}

func (x *SnapshotSchedule) GetSnapshotCount() int64 {
	if x, ok := x.GetRetentionPolicy().(*SnapshotSchedule_SnapshotCount); ok {
		return x.SnapshotCount
	}
	return 0
}

func (x *SnapshotSchedule) GetSnapshotSpec() *SnapshotSpec {
	if x != nil {
		return x.SnapshotSpec
	}
	return nil
}

type isSnapshotSchedule_RetentionPolicy interface {
	isSnapshotSchedule_RetentionPolicy()
}

type SnapshotSchedule_RetentionPeriod struct {
	// Retention period of the snapshot schedule. Once a snapshot created by the schedule reaches this age, it is
	// automatically deleted.
	RetentionPeriod *durationpb.Duration `protobuf:"bytes,9,opt,name=retention_period,json=retentionPeriod,proto3,oneof"`
}

type SnapshotSchedule_SnapshotCount struct {
	// Retention count of the snapshot schedule. Once the number of snapshots created by the schedule exceeds this
	// number, the oldest ones are automatically deleted. E.g. if the number is 5, the first snapshot is deleted
	// after the sixth one is created, the second is deleted after the seventh one is created, and so on.
	SnapshotCount int64 `protobuf:"varint,10,opt,name=snapshot_count,json=snapshotCount,proto3,oneof"`
}

func (*SnapshotSchedule_RetentionPeriod) isSnapshotSchedule_RetentionPolicy() {}

func (*SnapshotSchedule_SnapshotCount) isSnapshotSchedule_RetentionPolicy() {}

// A resource for frequency settings of a snapshot schedule.
type SchedulePolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Timestamp for creating the first snapshot.
	StartAt *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=start_at,json=startAt,proto3" json:"start_at,omitempty"`
	// Cron expression for the snapshot schedule (UTC+0).
	//
	// The expression must consist of five fields (`Minutes Hours Day-of-month Month Day-of-week`) or be one of
	// nonstandard predefined expressions (e.g. `@hourly`). For details about the format,
	// see [documentation](/docs/compute/concepts/snapshot-schedule#cron)
	Expression string `protobuf:"bytes,2,opt,name=expression,proto3" json:"expression,omitempty"`
}

func (x *SchedulePolicy) Reset() {
	*x = SchedulePolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SchedulePolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SchedulePolicy) ProtoMessage() {}

func (x *SchedulePolicy) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SchedulePolicy.ProtoReflect.Descriptor instead.
func (*SchedulePolicy) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescGZIP(), []int{1}
}

func (x *SchedulePolicy) GetStartAt() *timestamppb.Timestamp {
	if x != nil {
		return x.StartAt
	}
	return nil
}

func (x *SchedulePolicy) GetExpression() string {
	if x != nil {
		return x.Expression
	}
	return ""
}

// A resource for attributes of snapshots created by the snapshot schedule.
type SnapshotSpec struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Description of the created snapshot.
	Description string `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	// Snapshot labels as `key:value` pairs.
	Labels map[string]string `protobuf:"bytes,2,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SnapshotSpec) Reset() {
	*x = SnapshotSpec{}
	if protoimpl.UnsafeEnabled {
		mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SnapshotSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SnapshotSpec) ProtoMessage() {}

func (x *SnapshotSpec) ProtoReflect() protoreflect.Message {
	mi := &file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SnapshotSpec.ProtoReflect.Descriptor instead.
func (*SnapshotSpec) Descriptor() ([]byte, []int) {
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescGZIP(), []int{2}
}

func (x *SnapshotSpec) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *SnapshotSpec) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

var File_yandex_cloud_compute_v1_snapshot_schedule_proto protoreflect.FileDescriptor

var file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDesc = []byte{
	0x0a, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x63,
	0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x17, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8d, 0x06, 0x0a, 0x10,
	0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x1b, 0x0a, 0x09, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x49, 0x64, 0x12, 0x39, 0x0a,
	0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b,
	0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x4d,
	0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x35,
	0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f,
	0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f,
	0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x12, 0x48, 0x0a,
	0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x30, 0x2e,
	0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d,
	0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74,
	0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52,
	0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x50, 0x0a, 0x0f, 0x73, 0x63, 0x68, 0x65, 0x64,
	0x75, 0x6c, 0x65, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x27, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x68, 0x65, 0x64,
	0x75, 0x6c, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x0e, 0x73, 0x63, 0x68, 0x65, 0x64,
	0x75, 0x6c, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x46, 0x0a, 0x10, 0x72, 0x65, 0x74,
	0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x65, 0x72, 0x69, 0x6f, 0x64, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x48, 0x00,
	0x52, 0x0f, 0x72, 0x65, 0x74, 0x65, 0x6e, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x65, 0x72, 0x69, 0x6f,
	0x64, 0x12, 0x27, 0x0a, 0x0e, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x63, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x03, 0x48, 0x00, 0x52, 0x0d, 0x73, 0x6e, 0x61,
	0x70, 0x73, 0x68, 0x6f, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x4a, 0x0a, 0x0d, 0x73, 0x6e,
	0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x25, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64,
	0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70,
	0x73, 0x68, 0x6f, 0x74, 0x53, 0x70, 0x65, 0x63, 0x52, 0x0c, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68,
	0x6f, 0x74, 0x53, 0x70, 0x65, 0x63, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x64, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x16, 0x0a, 0x12, 0x53,
	0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45,
	0x44, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x43, 0x52, 0x45, 0x41, 0x54, 0x49, 0x4e, 0x47, 0x10,
	0x01, 0x12, 0x0a, 0x0a, 0x06, 0x41, 0x43, 0x54, 0x49, 0x56, 0x45, 0x10, 0x02, 0x12, 0x0c, 0x0a,
	0x08, 0x49, 0x4e, 0x41, 0x43, 0x54, 0x49, 0x56, 0x45, 0x10, 0x03, 0x12, 0x0c, 0x0a, 0x08, 0x44,
	0x45, 0x4c, 0x45, 0x54, 0x49, 0x4e, 0x47, 0x10, 0x04, 0x12, 0x0c, 0x0a, 0x08, 0x55, 0x50, 0x44,
	0x41, 0x54, 0x49, 0x4e, 0x47, 0x10, 0x05, 0x42, 0x12, 0x0a, 0x10, 0x72, 0x65, 0x74, 0x65, 0x6e,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22, 0x67, 0x0a, 0x0e, 0x53,
	0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x35, 0x0a,
	0x08, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x61, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x07, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x41, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x72, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x22, 0xb6, 0x01, 0x0a, 0x0c, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f,
	0x74, 0x53, 0x70, 0x65, 0x63, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x49, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78,
	0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76,
	0x31, 0x2e, 0x53, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x53, 0x70, 0x65, 0x63, 0x2e, 0x4c,
	0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65,
	0x6c, 0x73, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x62, 0x0a,
	0x1b, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x5a, 0x43, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2d,
	0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x67, 0x6f, 0x2d, 0x67, 0x65, 0x6e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x79, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x2f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2f, 0x63,
	0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x3b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74,
	0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescOnce sync.Once
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescData = file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDesc
)

func file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescGZIP() []byte {
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescOnce.Do(func() {
		file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescData = protoimpl.X.CompressGZIP(file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescData)
	})
	return file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDescData
}

var file_yandex_cloud_compute_v1_snapshot_schedule_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_yandex_cloud_compute_v1_snapshot_schedule_proto_goTypes = []interface{}{
	(SnapshotSchedule_Status)(0),  // 0: yandex.cloud.compute.v1.SnapshotSchedule.Status
	(*SnapshotSchedule)(nil),      // 1: yandex.cloud.compute.v1.SnapshotSchedule
	(*SchedulePolicy)(nil),        // 2: yandex.cloud.compute.v1.SchedulePolicy
	(*SnapshotSpec)(nil),          // 3: yandex.cloud.compute.v1.SnapshotSpec
	nil,                           // 4: yandex.cloud.compute.v1.SnapshotSchedule.LabelsEntry
	nil,                           // 5: yandex.cloud.compute.v1.SnapshotSpec.LabelsEntry
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),   // 7: google.protobuf.Duration
}
var file_yandex_cloud_compute_v1_snapshot_schedule_proto_depIdxs = []int32{
	6, // 0: yandex.cloud.compute.v1.SnapshotSchedule.created_at:type_name -> google.protobuf.Timestamp
	4, // 1: yandex.cloud.compute.v1.SnapshotSchedule.labels:type_name -> yandex.cloud.compute.v1.SnapshotSchedule.LabelsEntry
	0, // 2: yandex.cloud.compute.v1.SnapshotSchedule.status:type_name -> yandex.cloud.compute.v1.SnapshotSchedule.Status
	2, // 3: yandex.cloud.compute.v1.SnapshotSchedule.schedule_policy:type_name -> yandex.cloud.compute.v1.SchedulePolicy
	7, // 4: yandex.cloud.compute.v1.SnapshotSchedule.retention_period:type_name -> google.protobuf.Duration
	3, // 5: yandex.cloud.compute.v1.SnapshotSchedule.snapshot_spec:type_name -> yandex.cloud.compute.v1.SnapshotSpec
	6, // 6: yandex.cloud.compute.v1.SchedulePolicy.start_at:type_name -> google.protobuf.Timestamp
	5, // 7: yandex.cloud.compute.v1.SnapshotSpec.labels:type_name -> yandex.cloud.compute.v1.SnapshotSpec.LabelsEntry
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_yandex_cloud_compute_v1_snapshot_schedule_proto_init() }
func file_yandex_cloud_compute_v1_snapshot_schedule_proto_init() {
	if File_yandex_cloud_compute_v1_snapshot_schedule_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotSchedule); i {
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
		file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SchedulePolicy); i {
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
		file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SnapshotSpec); i {
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
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*SnapshotSchedule_RetentionPeriod)(nil),
		(*SnapshotSchedule_SnapshotCount)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_yandex_cloud_compute_v1_snapshot_schedule_proto_goTypes,
		DependencyIndexes: file_yandex_cloud_compute_v1_snapshot_schedule_proto_depIdxs,
		EnumInfos:         file_yandex_cloud_compute_v1_snapshot_schedule_proto_enumTypes,
		MessageInfos:      file_yandex_cloud_compute_v1_snapshot_schedule_proto_msgTypes,
	}.Build()
	File_yandex_cloud_compute_v1_snapshot_schedule_proto = out.File
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_rawDesc = nil
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_goTypes = nil
	file_yandex_cloud_compute_v1_snapshot_schedule_proto_depIdxs = nil
}
