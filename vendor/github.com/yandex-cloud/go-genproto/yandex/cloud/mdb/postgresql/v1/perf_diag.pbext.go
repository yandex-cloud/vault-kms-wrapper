// Code generated by protoc-gen-goext. DO NOT EDIT.

package postgresql

import (
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

func (m *SessionState) SetTime(v *timestamppb.Timestamp) {
	m.Time = v
}

func (m *SessionState) SetHost(v string) {
	m.Host = v
}

func (m *SessionState) SetPid(v int64) {
	m.Pid = v
}

func (m *SessionState) SetDatabase(v string) {
	m.Database = v
}

func (m *SessionState) SetUser(v string) {
	m.User = v
}

func (m *SessionState) SetApplicationName(v string) {
	m.ApplicationName = v
}

func (m *SessionState) SetBackendStart(v *timestamppb.Timestamp) {
	m.BackendStart = v
}

func (m *SessionState) SetXactStart(v *timestamppb.Timestamp) {
	m.XactStart = v
}

func (m *SessionState) SetQueryStart(v *timestamppb.Timestamp) {
	m.QueryStart = v
}

func (m *SessionState) SetStateChange(v *timestamppb.Timestamp) {
	m.StateChange = v
}

func (m *SessionState) SetWaitEventType(v string) {
	m.WaitEventType = v
}

func (m *SessionState) SetWaitEvent(v string) {
	m.WaitEvent = v
}

func (m *SessionState) SetState(v string) {
	m.State = v
}

func (m *SessionState) SetQuery(v string) {
	m.Query = v
}

func (m *SessionState) SetBackendType(v string) {
	m.BackendType = v
}

func (m *SessionState) SetClientAddr(v string) {
	m.ClientAddr = v
}

func (m *SessionState) SetClientHostname(v string) {
	m.ClientHostname = v
}

func (m *SessionState) SetClientPort(v int64) {
	m.ClientPort = v
}

func (m *SessionState) SetBackendXid(v int64) {
	m.BackendXid = v
}

func (m *SessionState) SetBackendXmin(v int64) {
	m.BackendXmin = v
}

func (m *SessionState) SetBlockingPids(v string) {
	m.BlockingPids = v
}

func (m *SessionState) SetQueryId(v string) {
	m.QueryId = v
}

func (m *PrimaryKey) SetHost(v string) {
	m.Host = v
}

func (m *PrimaryKey) SetUser(v string) {
	m.User = v
}

func (m *PrimaryKey) SetDatabase(v string) {
	m.Database = v
}

func (m *PrimaryKey) SetToplevel(v bool) {
	m.Toplevel = v
}

func (m *PrimaryKey) SetQueryId(v string) {
	m.QueryId = v
}

func (m *PrimaryKey) SetPlanId(v string) {
	m.PlanId = v
}

func (m *QueryStats) SetTime(v *timestamppb.Timestamp) {
	m.Time = v
}

func (m *QueryStats) SetQuery(v string) {
	m.Query = v
}

func (m *QueryStats) SetNormalizedPlan(v string) {
	m.NormalizedPlan = v
}

func (m *QueryStats) SetExamplePlan(v string) {
	m.ExamplePlan = v
}

func (m *QueryStats) SetPlans(v int64) {
	m.Plans = v
}

func (m *QueryStats) SetTotalPlanTime(v float64) {
	m.TotalPlanTime = v
}

func (m *QueryStats) SetMinPlanTime(v float64) {
	m.MinPlanTime = v
}

func (m *QueryStats) SetMaxPlanTime(v float64) {
	m.MaxPlanTime = v
}

func (m *QueryStats) SetMeanPlanTime(v float64) {
	m.MeanPlanTime = v
}

func (m *QueryStats) SetStddevPlanTime(v float64) {
	m.StddevPlanTime = v
}

func (m *QueryStats) SetCalls(v int64) {
	m.Calls = v
}

func (m *QueryStats) SetTotalTime(v float64) {
	m.TotalTime = v
}

func (m *QueryStats) SetMinTime(v float64) {
	m.MinTime = v
}

func (m *QueryStats) SetMaxTime(v float64) {
	m.MaxTime = v
}

func (m *QueryStats) SetMeanTime(v float64) {
	m.MeanTime = v
}

func (m *QueryStats) SetStddevTime(v float64) {
	m.StddevTime = v
}

func (m *QueryStats) SetRows(v int64) {
	m.Rows = v
}

func (m *QueryStats) SetSharedBlksHit(v int64) {
	m.SharedBlksHit = v
}

func (m *QueryStats) SetSharedBlksRead(v int64) {
	m.SharedBlksRead = v
}

func (m *QueryStats) SetSharedBlksDirtied(v int64) {
	m.SharedBlksDirtied = v
}

func (m *QueryStats) SetSharedBlksWritten(v int64) {
	m.SharedBlksWritten = v
}

func (m *QueryStats) SetLocalBlksHit(v int64) {
	m.LocalBlksHit = v
}

func (m *QueryStats) SetLocalBlksRead(v int64) {
	m.LocalBlksRead = v
}

func (m *QueryStats) SetLocalBlksDirtied(v int64) {
	m.LocalBlksDirtied = v
}

func (m *QueryStats) SetLocalBlksWritten(v int64) {
	m.LocalBlksWritten = v
}

func (m *QueryStats) SetTempBlksRead(v int64) {
	m.TempBlksRead = v
}

func (m *QueryStats) SetTempBlksWritten(v int64) {
	m.TempBlksWritten = v
}

func (m *QueryStats) SetBlkReadTime(v float64) {
	m.BlkReadTime = v
}

func (m *QueryStats) SetBlkWriteTime(v float64) {
	m.BlkWriteTime = v
}

func (m *QueryStats) SetTempBlkReadTime(v float64) {
	m.TempBlkReadTime = v
}

func (m *QueryStats) SetTempBlkWriteTime(v float64) {
	m.TempBlkWriteTime = v
}

func (m *QueryStats) SetWalRecords(v int64) {
	m.WalRecords = v
}

func (m *QueryStats) SetWalFpi(v int64) {
	m.WalFpi = v
}

func (m *QueryStats) SetWalBytes(v int64) {
	m.WalBytes = v
}

func (m *QueryStats) SetJitFunctions(v int64) {
	m.JitFunctions = v
}

func (m *QueryStats) SetJitGenerationTime(v float64) {
	m.JitGenerationTime = v
}

func (m *QueryStats) SetJitInliningCount(v int64) {
	m.JitInliningCount = v
}

func (m *QueryStats) SetJitInliningTime(v float64) {
	m.JitInliningTime = v
}

func (m *QueryStats) SetJitOptimizationCount(v int64) {
	m.JitOptimizationCount = v
}

func (m *QueryStats) SetJitOptimizationTime(v float64) {
	m.JitOptimizationTime = v
}

func (m *QueryStats) SetJitEmissionCount(v int64) {
	m.JitEmissionCount = v
}

func (m *QueryStats) SetJitEmissionTime(v float64) {
	m.JitEmissionTime = v
}

func (m *QueryStats) SetStartupCost(v int64) {
	m.StartupCost = v
}

func (m *QueryStats) SetTotalCost(v int64) {
	m.TotalCost = v
}

func (m *QueryStats) SetPlanRows(v int64) {
	m.PlanRows = v
}

func (m *QueryStats) SetPlanWidth(v int64) {
	m.PlanWidth = v
}

func (m *QueryStats) SetReads(v int64) {
	m.Reads = v
}

func (m *QueryStats) SetWrites(v int64) {
	m.Writes = v
}

func (m *QueryStats) SetUserTime(v float64) {
	m.UserTime = v
}

func (m *QueryStats) SetSystemTime(v float64) {
	m.SystemTime = v
}

func (m *QueryStatement) SetKey(v *PrimaryKey) {
	m.Key = v
}

func (m *QueryStatement) SetStats(v *QueryStats) {
	m.Stats = v
}