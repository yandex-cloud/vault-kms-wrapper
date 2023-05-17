// Code generated by protoc-gen-goext. DO NOT EDIT.

package compute

import (
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func (m *GpuCluster) SetId(v string) {
	m.Id = v
}

func (m *GpuCluster) SetFolderId(v string) {
	m.FolderId = v
}

func (m *GpuCluster) SetCreatedAt(v *timestamppb.Timestamp) {
	m.CreatedAt = v
}

func (m *GpuCluster) SetName(v string) {
	m.Name = v
}

func (m *GpuCluster) SetDescription(v string) {
	m.Description = v
}

func (m *GpuCluster) SetLabels(v map[string]string) {
	m.Labels = v
}

func (m *GpuCluster) SetStatus(v GpuCluster_Status) {
	m.Status = v
}

func (m *GpuCluster) SetZoneId(v string) {
	m.ZoneId = v
}

func (m *GpuCluster) SetInterconnectType(v GpuInterconnectType) {
	m.InterconnectType = v
}
