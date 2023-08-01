// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.17.3
// source: yandex/cloud/containerregistry/v1/registry_service.proto

package containerregistry

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
	RegistryService_Get_FullMethodName                  = "/yandex.cloud.containerregistry.v1.RegistryService/Get"
	RegistryService_List_FullMethodName                 = "/yandex.cloud.containerregistry.v1.RegistryService/List"
	RegistryService_Create_FullMethodName               = "/yandex.cloud.containerregistry.v1.RegistryService/Create"
	RegistryService_Update_FullMethodName               = "/yandex.cloud.containerregistry.v1.RegistryService/Update"
	RegistryService_Delete_FullMethodName               = "/yandex.cloud.containerregistry.v1.RegistryService/Delete"
	RegistryService_ListAccessBindings_FullMethodName   = "/yandex.cloud.containerregistry.v1.RegistryService/ListAccessBindings"
	RegistryService_SetAccessBindings_FullMethodName    = "/yandex.cloud.containerregistry.v1.RegistryService/SetAccessBindings"
	RegistryService_UpdateAccessBindings_FullMethodName = "/yandex.cloud.containerregistry.v1.RegistryService/UpdateAccessBindings"
	RegistryService_ListIpPermission_FullMethodName     = "/yandex.cloud.containerregistry.v1.RegistryService/ListIpPermission"
	RegistryService_SetIpPermission_FullMethodName      = "/yandex.cloud.containerregistry.v1.RegistryService/SetIpPermission"
	RegistryService_UpdateIpPermission_FullMethodName   = "/yandex.cloud.containerregistry.v1.RegistryService/UpdateIpPermission"
)

// RegistryServiceClient is the client API for RegistryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RegistryServiceClient interface {
	// Returns the specified Registry resource.
	//
	// To get the list of available Registry resources, make a [List] request.
	Get(ctx context.Context, in *GetRegistryRequest, opts ...grpc.CallOption) (*Registry, error)
	// Retrieves the list of Registry resources in the specified folder.
	List(ctx context.Context, in *ListRegistriesRequest, opts ...grpc.CallOption) (*ListRegistriesResponse, error)
	// Creates a registry in the specified folder.
	Create(ctx context.Context, in *CreateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Updates the specified registry.
	Update(ctx context.Context, in *UpdateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Deletes the specified registry.
	Delete(ctx context.Context, in *DeleteRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Lists access bindings for the specified registry.
	ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error)
	// Sets access bindings for the specified registry.
	SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Updates access bindings for the specified registry.
	UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// List ip permissions for the specified registry.
	ListIpPermission(ctx context.Context, in *ListIpPermissionRequest, opts ...grpc.CallOption) (*ListIpPermissionsResponse, error)
	// Set ip permissions for the specified registry.
	SetIpPermission(ctx context.Context, in *SetIpPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error)
	// Update ip permissions for the specified registry.
	UpdateIpPermission(ctx context.Context, in *UpdateIpPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error)
}

type registryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRegistryServiceClient(cc grpc.ClientConnInterface) RegistryServiceClient {
	return &registryServiceClient{cc}
}

func (c *registryServiceClient) Get(ctx context.Context, in *GetRegistryRequest, opts ...grpc.CallOption) (*Registry, error) {
	out := new(Registry)
	err := c.cc.Invoke(ctx, RegistryService_Get_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) List(ctx context.Context, in *ListRegistriesRequest, opts ...grpc.CallOption) (*ListRegistriesResponse, error) {
	out := new(ListRegistriesResponse)
	err := c.cc.Invoke(ctx, RegistryService_List_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Create(ctx context.Context, in *CreateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_Create_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Update(ctx context.Context, in *UpdateRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_Update_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) Delete(ctx context.Context, in *DeleteRegistryRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_Delete_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error) {
	out := new(access.ListAccessBindingsResponse)
	err := c.cc.Invoke(ctx, RegistryService_ListAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_SetAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_UpdateAccessBindings_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) ListIpPermission(ctx context.Context, in *ListIpPermissionRequest, opts ...grpc.CallOption) (*ListIpPermissionsResponse, error) {
	out := new(ListIpPermissionsResponse)
	err := c.cc.Invoke(ctx, RegistryService_ListIpPermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) SetIpPermission(ctx context.Context, in *SetIpPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_SetIpPermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) UpdateIpPermission(ctx context.Context, in *UpdateIpPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	out := new(operation.Operation)
	err := c.cc.Invoke(ctx, RegistryService_UpdateIpPermission_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RegistryServiceServer is the server API for RegistryService service.
// All implementations should embed UnimplementedRegistryServiceServer
// for forward compatibility
type RegistryServiceServer interface {
	// Returns the specified Registry resource.
	//
	// To get the list of available Registry resources, make a [List] request.
	Get(context.Context, *GetRegistryRequest) (*Registry, error)
	// Retrieves the list of Registry resources in the specified folder.
	List(context.Context, *ListRegistriesRequest) (*ListRegistriesResponse, error)
	// Creates a registry in the specified folder.
	Create(context.Context, *CreateRegistryRequest) (*operation.Operation, error)
	// Updates the specified registry.
	Update(context.Context, *UpdateRegistryRequest) (*operation.Operation, error)
	// Deletes the specified registry.
	Delete(context.Context, *DeleteRegistryRequest) (*operation.Operation, error)
	// Lists access bindings for the specified registry.
	ListAccessBindings(context.Context, *access.ListAccessBindingsRequest) (*access.ListAccessBindingsResponse, error)
	// Sets access bindings for the specified registry.
	SetAccessBindings(context.Context, *access.SetAccessBindingsRequest) (*operation.Operation, error)
	// Updates access bindings for the specified registry.
	UpdateAccessBindings(context.Context, *access.UpdateAccessBindingsRequest) (*operation.Operation, error)
	// List ip permissions for the specified registry.
	ListIpPermission(context.Context, *ListIpPermissionRequest) (*ListIpPermissionsResponse, error)
	// Set ip permissions for the specified registry.
	SetIpPermission(context.Context, *SetIpPermissionRequest) (*operation.Operation, error)
	// Update ip permissions for the specified registry.
	UpdateIpPermission(context.Context, *UpdateIpPermissionRequest) (*operation.Operation, error)
}

// UnimplementedRegistryServiceServer should be embedded to have forward compatible implementations.
type UnimplementedRegistryServiceServer struct {
}

func (UnimplementedRegistryServiceServer) Get(context.Context, *GetRegistryRequest) (*Registry, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedRegistryServiceServer) List(context.Context, *ListRegistriesRequest) (*ListRegistriesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedRegistryServiceServer) Create(context.Context, *CreateRegistryRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedRegistryServiceServer) Update(context.Context, *UpdateRegistryRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedRegistryServiceServer) Delete(context.Context, *DeleteRegistryRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedRegistryServiceServer) ListAccessBindings(context.Context, *access.ListAccessBindingsRequest) (*access.ListAccessBindingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAccessBindings not implemented")
}
func (UnimplementedRegistryServiceServer) SetAccessBindings(context.Context, *access.SetAccessBindingsRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetAccessBindings not implemented")
}
func (UnimplementedRegistryServiceServer) UpdateAccessBindings(context.Context, *access.UpdateAccessBindingsRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAccessBindings not implemented")
}
func (UnimplementedRegistryServiceServer) ListIpPermission(context.Context, *ListIpPermissionRequest) (*ListIpPermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListIpPermission not implemented")
}
func (UnimplementedRegistryServiceServer) SetIpPermission(context.Context, *SetIpPermissionRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetIpPermission not implemented")
}
func (UnimplementedRegistryServiceServer) UpdateIpPermission(context.Context, *UpdateIpPermissionRequest) (*operation.Operation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateIpPermission not implemented")
}

// UnsafeRegistryServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RegistryServiceServer will
// result in compilation errors.
type UnsafeRegistryServiceServer interface {
	mustEmbedUnimplementedRegistryServiceServer()
}

func RegisterRegistryServiceServer(s grpc.ServiceRegistrar, srv RegistryServiceServer) {
	s.RegisterService(&RegistryService_ServiceDesc, srv)
}

func _RegistryService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRegistryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Get_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Get(ctx, req.(*GetRegistryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRegistriesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_List_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).List(ctx, req.(*ListRegistriesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateRegistryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Create_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Create(ctx, req.(*CreateRegistryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateRegistryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Update_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Update(ctx, req.(*UpdateRegistryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteRegistryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_Delete_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).Delete(ctx, req.(*DeleteRegistryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_ListAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.ListAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).ListAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_ListAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).ListAccessBindings(ctx, req.(*access.ListAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_SetAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.SetAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).SetAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_SetAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).SetAccessBindings(ctx, req.(*access.SetAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_UpdateAccessBindings_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(access.UpdateAccessBindingsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).UpdateAccessBindings(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_UpdateAccessBindings_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).UpdateAccessBindings(ctx, req.(*access.UpdateAccessBindingsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_ListIpPermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListIpPermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).ListIpPermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_ListIpPermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).ListIpPermission(ctx, req.(*ListIpPermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_SetIpPermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetIpPermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).SetIpPermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_SetIpPermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).SetIpPermission(ctx, req.(*SetIpPermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistryService_UpdateIpPermission_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateIpPermissionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServiceServer).UpdateIpPermission(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: RegistryService_UpdateIpPermission_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServiceServer).UpdateIpPermission(ctx, req.(*UpdateIpPermissionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RegistryService_ServiceDesc is the grpc.ServiceDesc for RegistryService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RegistryService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "yandex.cloud.containerregistry.v1.RegistryService",
	HandlerType: (*RegistryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Get",
			Handler:    _RegistryService_Get_Handler,
		},
		{
			MethodName: "List",
			Handler:    _RegistryService_List_Handler,
		},
		{
			MethodName: "Create",
			Handler:    _RegistryService_Create_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _RegistryService_Update_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _RegistryService_Delete_Handler,
		},
		{
			MethodName: "ListAccessBindings",
			Handler:    _RegistryService_ListAccessBindings_Handler,
		},
		{
			MethodName: "SetAccessBindings",
			Handler:    _RegistryService_SetAccessBindings_Handler,
		},
		{
			MethodName: "UpdateAccessBindings",
			Handler:    _RegistryService_UpdateAccessBindings_Handler,
		},
		{
			MethodName: "ListIpPermission",
			Handler:    _RegistryService_ListIpPermission_Handler,
		},
		{
			MethodName: "SetIpPermission",
			Handler:    _RegistryService_SetIpPermission_Handler,
		},
		{
			MethodName: "UpdateIpPermission",
			Handler:    _RegistryService_UpdateIpPermission_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "yandex/cloud/containerregistry/v1/registry_service.proto",
}
