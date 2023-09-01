// Code generated by sdkgen. DO NOT EDIT.

// nolint
package compute

import (
	"context"

	"google.golang.org/grpc"

	compute "github.com/yandex-cloud/go-genproto/yandex/cloud/compute/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// DiskPlacementGroupServiceClient is a compute.DiskPlacementGroupServiceClient with
// lazy GRPC connection initialization.
type DiskPlacementGroupServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Create implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) Create(ctx context.Context, in *compute.CreateDiskPlacementGroupRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).Create(ctx, in, opts...)
}

// Delete implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) Delete(ctx context.Context, in *compute.DeleteDiskPlacementGroupRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) Get(ctx context.Context, in *compute.GetDiskPlacementGroupRequest, opts ...grpc.CallOption) (*compute.DiskPlacementGroup, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).Get(ctx, in, opts...)
}

// List implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) List(ctx context.Context, in *compute.ListDiskPlacementGroupsRequest, opts ...grpc.CallOption) (*compute.ListDiskPlacementGroupsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).List(ctx, in, opts...)
}

type DiskPlacementGroupIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *DiskPlacementGroupServiceClient
	request *compute.ListDiskPlacementGroupsRequest

	items []*compute.DiskPlacementGroup
}

func (c *DiskPlacementGroupServiceClient) DiskPlacementGroupIterator(ctx context.Context, req *compute.ListDiskPlacementGroupsRequest, opts ...grpc.CallOption) *DiskPlacementGroupIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &DiskPlacementGroupIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *DiskPlacementGroupIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	if it.requestedSize == 0 || it.requestedSize > it.pageSize {
		it.request.PageSize = it.pageSize
	} else {
		it.request.PageSize = it.requestedSize
	}

	response, err := it.client.List(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.DiskPlacementGroups
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *DiskPlacementGroupIterator) Take(size int64) ([]*compute.DiskPlacementGroup, error) {
	if it.err != nil {
		return nil, it.err
	}

	if size == 0 {
		size = 1 << 32 // something insanely large
	}
	it.requestedSize = size
	defer func() {
		// reset iterator for future calls.
		it.requestedSize = 0
	}()

	var result []*compute.DiskPlacementGroup

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *DiskPlacementGroupIterator) TakeAll() ([]*compute.DiskPlacementGroup, error) {
	return it.Take(0)
}

func (it *DiskPlacementGroupIterator) Value() *compute.DiskPlacementGroup {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *DiskPlacementGroupIterator) Error() error {
	return it.err
}

// ListDisks implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) ListDisks(ctx context.Context, in *compute.ListDiskPlacementGroupDisksRequest, opts ...grpc.CallOption) (*compute.ListDiskPlacementGroupDisksResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).ListDisks(ctx, in, opts...)
}

type DiskPlacementGroupDisksIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *DiskPlacementGroupServiceClient
	request *compute.ListDiskPlacementGroupDisksRequest

	items []*compute.Disk
}

func (c *DiskPlacementGroupServiceClient) DiskPlacementGroupDisksIterator(ctx context.Context, req *compute.ListDiskPlacementGroupDisksRequest, opts ...grpc.CallOption) *DiskPlacementGroupDisksIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &DiskPlacementGroupDisksIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *DiskPlacementGroupDisksIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	if it.requestedSize == 0 || it.requestedSize > it.pageSize {
		it.request.PageSize = it.pageSize
	} else {
		it.request.PageSize = it.requestedSize
	}

	response, err := it.client.ListDisks(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Disks
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *DiskPlacementGroupDisksIterator) Take(size int64) ([]*compute.Disk, error) {
	if it.err != nil {
		return nil, it.err
	}

	if size == 0 {
		size = 1 << 32 // something insanely large
	}
	it.requestedSize = size
	defer func() {
		// reset iterator for future calls.
		it.requestedSize = 0
	}()

	var result []*compute.Disk

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *DiskPlacementGroupDisksIterator) TakeAll() ([]*compute.Disk, error) {
	return it.Take(0)
}

func (it *DiskPlacementGroupDisksIterator) Value() *compute.Disk {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *DiskPlacementGroupDisksIterator) Error() error {
	return it.err
}

// ListOperations implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) ListOperations(ctx context.Context, in *compute.ListDiskPlacementGroupOperationsRequest, opts ...grpc.CallOption) (*compute.ListDiskPlacementGroupOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).ListOperations(ctx, in, opts...)
}

type DiskPlacementGroupOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *DiskPlacementGroupServiceClient
	request *compute.ListDiskPlacementGroupOperationsRequest

	items []*operation.Operation
}

func (c *DiskPlacementGroupServiceClient) DiskPlacementGroupOperationsIterator(ctx context.Context, req *compute.ListDiskPlacementGroupOperationsRequest, opts ...grpc.CallOption) *DiskPlacementGroupOperationsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &DiskPlacementGroupOperationsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *DiskPlacementGroupOperationsIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started && it.request.PageToken == "" {
		return false
	}
	it.started = true

	if it.requestedSize == 0 || it.requestedSize > it.pageSize {
		it.request.PageSize = it.pageSize
	} else {
		it.request.PageSize = it.requestedSize
	}

	response, err := it.client.ListOperations(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Operations
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *DiskPlacementGroupOperationsIterator) Take(size int64) ([]*operation.Operation, error) {
	if it.err != nil {
		return nil, it.err
	}

	if size == 0 {
		size = 1 << 32 // something insanely large
	}
	it.requestedSize = size
	defer func() {
		// reset iterator for future calls.
		it.requestedSize = 0
	}()

	var result []*operation.Operation

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *DiskPlacementGroupOperationsIterator) TakeAll() ([]*operation.Operation, error) {
	return it.Take(0)
}

func (it *DiskPlacementGroupOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *DiskPlacementGroupOperationsIterator) Error() error {
	return it.err
}

// Update implements compute.DiskPlacementGroupServiceClient
func (c *DiskPlacementGroupServiceClient) Update(ctx context.Context, in *compute.UpdateDiskPlacementGroupRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return compute.NewDiskPlacementGroupServiceClient(conn).Update(ctx, in, opts...)
}
