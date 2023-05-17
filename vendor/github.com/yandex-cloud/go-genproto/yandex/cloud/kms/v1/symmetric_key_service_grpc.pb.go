// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.17.3
// source: yandex/cloud/kms/v1/symmetric_key_service.proto

package kms

import (
	context "context"
	access "github.com/yandex-cloud/go-genproto/yandex/cloud/access"
	operation "github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SymmetricKeyService_Create_FullMethodName                     = "/yandex.cloud.kms.v1.SymmetricKeyService/Create"
	SymmetricKeyService_Get_FullMethodName                        = "/yandex.cloud.kms.v1.SymmetricKeyService/Get"
	SymmetricKeyService_List_FullMethodName                       = "/yandex.cloud.kms.v1.SymmetricKeyService/List"
	SymmetricKeyService_ListVersions_FullMethodName               = "/yandex.cloud.kms.v1.SymmetricKeyService/ListVersions"
	SymmetricKeyService_Update_FullMethodName                     = "/yandex.cloud.kms.v1.SymmetricKeyService/Update"
	SymmetricKeyService_Delete_FullMethodName                     = "/yandex.cloud.kms.v1.SymmetricKeyService/Delete"
	SymmetricKeyService_SetPrimaryVersion_FullMethodName          = "/yandex.cloud.kms.v1.SymmetricKeyService/SetPrimaryVersion"
	SymmetricKeyService_ScheduleVersionDestruction_FullMethodName = "/yandex.cloud.kms.v1.SymmetricKeyService/ScheduleVersionDestruction"
	SymmetricKeyService_CancelVersionDestruction_FullMethodName   = "/yandex.cloud.kms.v1.SymmetricKeyService/CancelVersionDestruction"
	SymmetricKeyService_Rotate_FullMethodName                     = "/yandex.cloud.kms.v1.SymmetricKeyService/Rotate"
	SymmetricKeyService_ListOperations_FullMethodName             = "/yandex.cloud.kms.v1.SymmetricKeyService/ListOperations"
	SymmetricKeyService_ListAccessBindings_FullMethodName         = "/yandex.cloud.kms.v1.SymmetricKeyService/ListAccessBindings"
	SymmetricKeyService_SetAccessBindings_FullMethodName          = "/yandex.cloud.kms.v1.SymmetricKeyService/SetAccessBindings"
	SymmetricKeyService_UpdateAccessBindings_FullMethodName       = "/yandex.cloud.kms.v1.SymmetricKeyService/UpdateAccessBindings"
)

// SymmetricKeyServiceClient is the client API for SymmetricKeyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SymmetricKeyServiceClient interface {
	// Creates a symmetric KMS key in the specified folder.
	Create(ctx context.Context, in *CreateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Returns the specified symmetric KMS key.
	//
	//	To get the list of available symmetric KMS keys, make a [SymmetricKeyService.List] request.
	Get(ctx context.Context, in *GetSymmetricKeyRequest, opts ...grpc.CallOption) (*SymmetricKey, error)
	// Returns the list of symmetric KMS keys in the specified folder.
	List(ctx context.Context, in *ListSymmetricKeysRequest, opts ...grpc.CallOption) (*ListSymmetricKeysResponse, error)
	// Returns the list of versions of the specified symmetric KMS key.
	ListVersions(ctx context.Context, in *ListSymmetricKeyVersionsRequest, opts ...grpc.CallOption) (*ListSymmetricKeyVersionsResponse, error)
	// Updates the specified symmetric KMS key.
	Update(ctx context.Context, in *UpdateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Deletes the specified symmetric KMS key. This action also automatically schedules
	// the destruction of all of the key's versions in 72 hours.
	//
	// The key and its versions appear absent in [SymmetricKeyService.Get] and [SymmetricKeyService.List]
	// requests, but can be restored within 72 hours with a request to tech support.
	Delete(ctx context.Context, in *DeleteSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Sets the primary version for the specified key. The primary version is used
	// by default for all encrypt/decrypt operations where no version ID is specified.
	SetPrimaryVersion(ctx context.Context, in *SetPrimarySymmetricKeyVersionRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Schedules the specified key version for destruction.
	//
	// Scheduled destruction can be cancelled with the [SymmetricKeyService.CancelVersionDestruction] method.
	ScheduleVersionDestruction(ctx context.Context, in *ScheduleSymmetricKeyVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Cancels previously scheduled version destruction, if the version hasn't been destroyed yet.
	CancelVersionDestruction(ctx context.Context, in *CancelSymmetricKeyVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Rotates the specified key: creates a new key version and makes it the primary version.
	// The old version remains available for decryption of ciphertext encrypted with it.
	Rotate(ctx context.Context, in *RotateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Lists operations for the specified symmetric KMS key.
	ListOperations(ctx context.Context, in *ListSymmetricKeyOperationsRequest, opts ...grpc.CallOption) (*ListSymmetricKeyOperationsResponse, error)
	// Lists existing access bindings for the specified key.
	ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error)
	// Sets access bindings for the key.
	SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Updates access bindings for the specified key.
	UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error)
}

type symmetricKeyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSymmetricKeyServiceClient(cc grpc.ClientConnInterface) SymmetricKeyServiceClient {
	return &symmetricKeyServiceClient{cc}
}

func (c *symmetricKeyServiceClient) Create(ctx context.Context, in *CreateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_Create_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) Get(ctx context.Context, in *GetSymmetricKeyRequest, opts ...grpc.CallOption) (*SymmetricKey, error) {
	out := new(SymmetricKey)
	err := c.cc.Invoke(ctx, SymmetricKeyService_Get_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) List(ctx context.Context, in *ListSymmetricKeysRequest, opts ...grpc.CallOption) (*ListSymmetricKeysResponse, error) {
	out := new(ListSymmetricKeysResponse)
	err := c.cc.Invoke(ctx, SymmetricKeyService_List_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) ListVersions(ctx context.Context, in *ListSymmetricKeyVersionsRequest, opts ...grpc.CallOption) (*ListSymmetricKeyVersionsResponse, error) {
	out := new(ListSymmetricKeyVersionsResponse)
	err := c.cc.Invoke(ctx, SymmetricKeyService_ListVersions_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) Update(ctx context.Context, in *UpdateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_Update_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) Delete(ctx context.Context, in *DeleteSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_Delete_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) SetPrimaryVersion(ctx context.Context, in *SetPrimarySymmetricKeyVersionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_SetPrimaryVersion_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) ScheduleVersionDestruction(ctx context.Context, in *ScheduleSymmetricKeyVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_ScheduleVersionDestruction_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) CancelVersionDestruction(ctx context.Context, in *CancelSymmetricKeyVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_CancelVersionDestruction_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) Rotate(ctx context.Context, in *RotateSymmetricKeyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_Rotate_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) ListOperations(ctx context.Context, in *ListSymmetricKeyOperationsRequest, opts ...grpc.CallOption) (*ListSymmetricKeyOperationsResponse, error) {
	out := new(ListSymmetricKeyOperationsResponse)
	err := c.cc.Invoke(ctx, SymmetricKeyService_ListOperations_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error) {
	out := new(access.ListAccessBindingsResponse)
	err := c.cc.Invoke(ctx, SymmetricKeyService_ListAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_SetAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *symmetricKeyServiceClient) UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, SymmetricKeyService_UpdateAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SymmetricKeyServiceServer is the server API for SymmetricKeyService service.
// All implementations should embed UnimplementedSymmetricKeyServiceServer
// for forward compatibility
type SymmetricKeyServiceServer interface {
	// Creates a symmetric KMS key in the specified folder.
	Create(context.Context, *CreateSymmetricKeyRequest) (*operation.Operation, error)
	// Returns the specified symmetric KMS key.
	//
	//	To get the list of available symmetric KMS keys, make a [SymmetricKeyService.List] request.
	Get(context.Context, *GetSymmetricKeyRequest) (*SymmetricKey, error)
	// Returns the list of symmetric KMS keys in the specified folder.
	List(context.Context, *ListSymmetricKeysRequest) (*ListSymmetricKeysResponse, error)
	// Returns the list of versions of the specified symmetric KMS key.
	ListVersions(context.Context, *ListSymmetricKeyVersionsRequest) (*ListSymmetricKeyVersionsResponse, error)
	// Updates the specified symmetric KMS key.
	Update(context.Context, *UpdateSymmetricKeyRequest) (*operation.Operation, error)
	// Deletes the specified symmetric KMS key. This action also automatically schedules
	// the destruction of all of the key's versions in 72 hours.
	//
	// The key and its versions appear absent in [SymmetricKeyService.Get] and [SymmetricKeyService.List]
	// requests, but can be restored within 72 hours with a request to tech support.
	Delete(context.Context, *DeleteSymmetricKeyRequest) (*operation.Operation, error)
	// Sets the primary version for the specified key. The primary version is used
	// by default for all encrypt/decrypt operations where no version ID is specified.
	SetPrimaryVersion(context.Context, *SetPrimarySymmetricKeyVersionRequest) (*operation.Operation, error)
	// Schedules the specified key version for destruction.
	//
	// Scheduled destruction can be cancelled with the [SymmetricKeyService.CancelVersionDestruction] method.
	ScheduleVersionDestruction(context.Context, *ScheduleSymmetricKeyVersionDestructionRequest) (*operation.Operation, error)
	// Cancels previously scheduled version destruction, if the version hasn't been destroyed yet.
	CancelVersionDestruction(context.Context, *CancelSymmetricKeyVersionDestructionRequest) (*operation.Operation, error)
	// Rotates the specified key: creates a new key version and makes it the primary version.
	// The old version remains available for decryption of ciphertext encrypted with it.
	Rotate(context.Context, *RotateSymmetricKeyRequest) (*operation.Operation, error)
	// Lists operations for the specified symmetric KMS key.
	ListOperations(context.Context, *ListSymmetricKeyOperationsRequest) (*ListSymmetricKeyOperationsResponse, error)
	// Lists existing access bindings for the specified key.
	ListAccessBindings(context.Context, *access.ListAccessBindingsRequest) (*access.ListAccessBindingsResponse, error)
	// Sets access bindings for the key.
	SetAccessBindings(context.Context, *access.SetAccessBindingsRequest) (*operation.Operation, error)
	// Updates access bindings for the specified key.
	UpdateAccessBindings(context.Context, *access.UpdateAccessBindingsRequest) (*operation.Operation, error)
}

// UnimplementedSymmetricKeyServiceServer should be embedded to have forward compatible implementations.
type UnimplementedSymmetricKeyServiceServer struct {
}

func (UnimplementedSymmetricKeyServiceServer) Create(context.Context, *CreateSymmetricKeyRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) Get(context.Context, *GetSymmetricKeyRequest) (*SymmetricKey, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) List(context.Context, *ListSymmetricKeysRequest) (*ListSymmetricKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) ListVersions(context.Context, *ListSymmetricKeyVersionsRequest) (*ListSymmetricKeyVersionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListVersions not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) Update(context.Context, *UpdateSymmetricKeyRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) Delete(context.Context, *DeleteSymmetricKeyRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) SetPrimaryVersion(context.Context, *SetPrimarySymmetricKeyVersionRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPrimaryVersion not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) ScheduleVersionDestruction(context.Context, *ScheduleSymmetricKeyVersionDestructionRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ScheduleVersionDestruction not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) CancelVersionDestruction(context.Context, *CancelSymmetricKeyVersionDestructionRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CancelVersionDestruction not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) Rotate(context.Context, *RotateSymmetricKeyRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Rotate not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) ListOperations(context.Context, *ListSymmetricKeyOperationsRequest) (*ListSymmetricKeyOperationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListOperations not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) ListAccessBindings(context.Context, *access.ListAccessBindingsRequest) (*access.ListAccessBindingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAccessBindings not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) SetAccessBindings(context.Context, *access.SetAccessBindingsRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetAccessBindings not implemented")
}
func (UnimplementedSymmetricKeyServiceServer) UpdateAccessBindings(context.Context, *access.UpdateAccessBindingsRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccessBindings not implemented")
}

// UnsafeSymmetricKeyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SymmetricKeyServiceServer will
// result in compilation errors.
type UnsafeSymmetricKeyServiceServer interface {
	mustEmbedUnimplementedSymmetricKeyServiceServer()
}

func RegisterSymmetricKeyServiceServer(s grpc.ServiceRegistrar, srv SymmetricKeyServiceServer) {
	s.RegisterService(&SymmetricKeyService_ServiceDesc, srv)
}

func _SymmetricKeyService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSymmetricKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_Create_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).Create(ctx, req.(*CreateSymmetricKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetSymmetricKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_Get_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).Get(ctx, req.(*GetSymmetricKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSymmetricKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_List_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).List(ctx, req.(*ListSymmetricKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_ListVersions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSymmetricKeyVersionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).ListVersions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_ListVersions_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).ListVersions(ctx, req.(*ListSymmetricKeyVersionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateSymmetricKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_Update_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).Update(ctx, req.(*UpdateSymmetricKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSymmetricKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_Delete_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).Delete(ctx, req.(*DeleteSymmetricKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_SetPrimaryVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetPrimarySymmetricKeyVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).SetPrimaryVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_SetPrimaryVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).SetPrimaryVersion(ctx, req.(*SetPrimarySymmetricKeyVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_ScheduleVersionDestruction_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ScheduleSymmetricKeyVersionDestructionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).ScheduleVersionDestruction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_ScheduleVersionDestruction_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).ScheduleVersionDestruction(ctx, req.(*ScheduleSymmetricKeyVersionDestructionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_CancelVersionDestruction_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CancelSymmetricKeyVersionDestructionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).CancelVersionDestruction(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_CancelVersionDestruction_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).CancelVersionDestruction(ctx, req.(*CancelSymmetricKeyVersionDestructionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_Rotate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RotateSymmetricKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).Rotate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_Rotate_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).Rotate(ctx, req.(*RotateSymmetricKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_ListOperations_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListSymmetricKeyOperationsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).ListOperations(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_ListOperations_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).ListOperations(ctx, req.(*ListSymmetricKeyOperationsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_ListAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.ListAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).ListAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_ListAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).ListAccessBindings(ctx, req.(*access.ListAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_SetAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.SetAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).SetAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_SetAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).SetAccessBindings(ctx, req.(*access.SetAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SymmetricKeyService_UpdateAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.UpdateAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SymmetricKeyServiceServer).UpdateAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SymmetricKeyService_UpdateAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SymmetricKeyServiceServer).UpdateAccessBindings(ctx, req.(*access.UpdateAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SymmetricKeyService_ServiceDesc is the grpc.ServiceDesc for SymmetricKeyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SymmetricKeyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "yandex.cloud.kms.v1.SymmetricKeyService",
	HandlerType: (*SymmetricKeyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Create",
			Handler:    _SymmetricKeyService_Create_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _SymmetricKeyService_Get_Handler,
		},
		{
			MethodName: "List",
			Handler:    _SymmetricKeyService_List_Handler,
		},
		{
			MethodName: "ListVersions",
			Handler:    _SymmetricKeyService_ListVersions_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _SymmetricKeyService_Update_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _SymmetricKeyService_Delete_Handler,
		},
		{
			MethodName: "SetPrimaryVersion",
			Handler:    _SymmetricKeyService_SetPrimaryVersion_Handler,
		},
		{
			MethodName: "ScheduleVersionDestruction",
			Handler:    _SymmetricKeyService_ScheduleVersionDestruction_Handler,
		},
		{
			MethodName: "CancelVersionDestruction",
			Handler:    _SymmetricKeyService_CancelVersionDestruction_Handler,
		},
		{
			MethodName: "Rotate",
			Handler:    _SymmetricKeyService_Rotate_Handler,
		},
		{
			MethodName: "ListOperations",
			Handler:    _SymmetricKeyService_ListOperations_Handler,
		},
		{
			MethodName: "ListAccessBindings",
			Handler:    _SymmetricKeyService_ListAccessBindings_Handler,
		},
		{
			MethodName: "SetAccessBindings",
			Handler:    _SymmetricKeyService_SetAccessBindings_Handler,
		},
		{
			MethodName: "UpdateAccessBindings",
			Handler:    _SymmetricKeyService_UpdateAccessBindings_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "yandex/cloud/kms/v1/symmetric_key_service.proto",
}
