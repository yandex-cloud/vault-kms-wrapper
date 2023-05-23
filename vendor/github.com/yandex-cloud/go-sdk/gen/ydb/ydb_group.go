// Code generated by sdkgen. DO NOT EDIT.

package ydb

import (
	"context"

	"google.golang.org/grpc"
)

// YDB provides access to "ydb" component of Yandex.Cloud
type YDB struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// NewYDB creates instance of YDB
func NewYDB(g func(ctx context.Context) (*grpc.ClientConn, error)) *YDB {
	return &YDB{g}
}

// Database gets DatabaseService client
func (y *YDB) Database() *DatabaseServiceClient {
	return &DatabaseServiceClient{getConn: y.getConn}
}

// ResourcePreset gets ResourcePresetService client
func (y *YDB) ResourcePreset() *ResourcePresetServiceClient {
	return &ResourcePresetServiceClient{getConn: y.getConn}
}

// StorageType gets StorageTypeService client
func (y *YDB) StorageType() *StorageTypeServiceClient {
	return &StorageTypeServiceClient{getConn: y.getConn}
}

// Backup gets BackupService client
func (y *YDB) Backup() *BackupServiceClient {
	return &BackupServiceClient{getConn: y.getConn}
}
