// Code generated by protoc-gen-goext. DO NOT EDIT.

package greenplum

import (
	timeofday "google.golang.org/genproto/googleapis/type/timeofday"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func (m *Cluster) SetId(v string) {
	m.Id = v
}

func (m *Cluster) SetFolderId(v string) {
	m.FolderId = v
}

func (m *Cluster) SetCreatedAt(v *timestamppb.Timestamp) {
	m.CreatedAt = v
}

func (m *Cluster) SetName(v string) {
	m.Name = v
}

func (m *Cluster) SetConfig(v *GreenplumConfig) {
	m.Config = v
}

func (m *Cluster) SetDescription(v string) {
	m.Description = v
}

func (m *Cluster) SetLabels(v map[string]string) {
	m.Labels = v
}

func (m *Cluster) SetEnvironment(v Cluster_Environment) {
	m.Environment = v
}

func (m *Cluster) SetMonitoring(v []*Monitoring) {
	m.Monitoring = v
}

func (m *Cluster) SetMasterConfig(v *MasterSubclusterConfig) {
	m.MasterConfig = v
}

func (m *Cluster) SetSegmentConfig(v *SegmentSubclusterConfig) {
	m.SegmentConfig = v
}

func (m *Cluster) SetMasterHostCount(v int64) {
	m.MasterHostCount = v
}

func (m *Cluster) SetSegmentHostCount(v int64) {
	m.SegmentHostCount = v
}

func (m *Cluster) SetSegmentInHost(v int64) {
	m.SegmentInHost = v
}

func (m *Cluster) SetNetworkId(v string) {
	m.NetworkId = v
}

func (m *Cluster) SetHealth(v Cluster_Health) {
	m.Health = v
}

func (m *Cluster) SetStatus(v Cluster_Status) {
	m.Status = v
}

func (m *Cluster) SetMaintenanceWindow(v *MaintenanceWindow) {
	m.MaintenanceWindow = v
}

func (m *Cluster) SetPlannedOperation(v *MaintenanceOperation) {
	m.PlannedOperation = v
}

func (m *Cluster) SetSecurityGroupIds(v []string) {
	m.SecurityGroupIds = v
}

func (m *Cluster) SetUserName(v string) {
	m.UserName = v
}

func (m *Cluster) SetDeletionProtection(v bool) {
	m.DeletionProtection = v
}

func (m *Cluster) SetHostGroupIds(v []string) {
	m.HostGroupIds = v
}

func (m *Cluster) SetClusterConfig(v *ClusterConfigSet) {
	m.ClusterConfig = v
}

type ClusterConfigSet_GreenplumConfig = isClusterConfigSet_GreenplumConfig

func (m *ClusterConfigSet) SetGreenplumConfig(v ClusterConfigSet_GreenplumConfig) {
	m.GreenplumConfig = v
}

func (m *ClusterConfigSet) SetGreenplumConfigSet_6_17(v *GreenplumConfigSet6_17) {
	m.GreenplumConfig = &ClusterConfigSet_GreenplumConfigSet_6_17{
		GreenplumConfigSet_6_17: v,
	}
}

func (m *ClusterConfigSet) SetGreenplumConfigSet_6_19(v *GreenplumConfigSet6_19) {
	m.GreenplumConfig = &ClusterConfigSet_GreenplumConfigSet_6_19{
		GreenplumConfigSet_6_19: v,
	}
}

func (m *ClusterConfigSet) SetGreenplumConfigSet_6_21(v *GreenplumConfigSet6_21) {
	m.GreenplumConfig = &ClusterConfigSet_GreenplumConfigSet_6_21{
		GreenplumConfigSet_6_21: v,
	}
}

func (m *ClusterConfigSet) SetGreenplumConfigSet_6_22(v *GreenplumConfigSet6_22) {
	m.GreenplumConfig = &ClusterConfigSet_GreenplumConfigSet_6_22{
		GreenplumConfigSet_6_22: v,
	}
}

func (m *ClusterConfigSet) SetPool(v *ConnectionPoolerConfigSet) {
	m.Pool = v
}

func (m *Monitoring) SetName(v string) {
	m.Name = v
}

func (m *Monitoring) SetDescription(v string) {
	m.Description = v
}

func (m *Monitoring) SetLink(v string) {
	m.Link = v
}

func (m *GreenplumConfig) SetVersion(v string) {
	m.Version = v
}

func (m *GreenplumConfig) SetBackupWindowStart(v *timeofday.TimeOfDay) {
	m.BackupWindowStart = v
}

func (m *GreenplumConfig) SetAccess(v *Access) {
	m.Access = v
}

func (m *GreenplumConfig) SetZoneId(v string) {
	m.ZoneId = v
}

func (m *GreenplumConfig) SetSubnetId(v string) {
	m.SubnetId = v
}

func (m *GreenplumConfig) SetAssignPublicIp(v bool) {
	m.AssignPublicIp = v
}

func (m *Access) SetDataLens(v bool) {
	m.DataLens = v
}

func (m *Access) SetWebSql(v bool) {
	m.WebSql = v
}

func (m *Access) SetDataTransfer(v bool) {
	m.DataTransfer = v
}

func (m *GreenplumRestoreConfig) SetBackupWindowStart(v *timeofday.TimeOfDay) {
	m.BackupWindowStart = v
}

func (m *GreenplumRestoreConfig) SetAccess(v *Access) {
	m.Access = v
}

func (m *GreenplumRestoreConfig) SetZoneId(v string) {
	m.ZoneId = v
}

func (m *GreenplumRestoreConfig) SetSubnetId(v string) {
	m.SubnetId = v
}

func (m *GreenplumRestoreConfig) SetAssignPublicIp(v bool) {
	m.AssignPublicIp = v
}

func (m *RestoreResources) SetResourcePresetId(v string) {
	m.ResourcePresetId = v
}

func (m *RestoreResources) SetDiskSize(v int64) {
	m.DiskSize = v
}
