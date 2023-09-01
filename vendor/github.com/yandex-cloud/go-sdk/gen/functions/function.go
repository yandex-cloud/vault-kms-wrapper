// Code generated by sdkgen. DO NOT EDIT.

// nolint
package functions

import (
	"context"

	"google.golang.org/grpc"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/access"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
	functions "github.com/yandex-cloud/go-genproto/yandex/cloud/serverless/functions/v1"
)

//revive:disable

// FunctionServiceClient is a functions.FunctionServiceClient with
// lazy GRPC connection initialization.
type FunctionServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Create implements functions.FunctionServiceClient
func (c *FunctionServiceClient) Create(ctx context.Context, in *functions.CreateFunctionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).Create(ctx, in, opts...)
}

// CreateVersion implements functions.FunctionServiceClient
func (c *FunctionServiceClient) CreateVersion(ctx context.Context, in *functions.CreateFunctionVersionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).CreateVersion(ctx, in, opts...)
}

// Delete implements functions.FunctionServiceClient
func (c *FunctionServiceClient) Delete(ctx context.Context, in *functions.DeleteFunctionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements functions.FunctionServiceClient
func (c *FunctionServiceClient) Get(ctx context.Context, in *functions.GetFunctionRequest, opts ...grpc.CallOption) (*functions.Function, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).Get(ctx, in, opts...)
}

// GetVersion implements functions.FunctionServiceClient
func (c *FunctionServiceClient) GetVersion(ctx context.Context, in *functions.GetFunctionVersionRequest, opts ...grpc.CallOption) (*functions.Version, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).GetVersion(ctx, in, opts...)
}

// GetVersionByTag implements functions.FunctionServiceClient
func (c *FunctionServiceClient) GetVersionByTag(ctx context.Context, in *functions.GetFunctionVersionByTagRequest, opts ...grpc.CallOption) (*functions.Version, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).GetVersionByTag(ctx, in, opts...)
}

// List implements functions.FunctionServiceClient
func (c *FunctionServiceClient) List(ctx context.Context, in *functions.ListFunctionsRequest, opts ...grpc.CallOption) (*functions.ListFunctionsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).List(ctx, in, opts...)
}

type FunctionIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListFunctionsRequest

	items []*functions.Function
}

func (c *FunctionServiceClient) FunctionIterator(ctx context.Context, req *functions.ListFunctionsRequest, opts ...grpc.CallOption) *FunctionIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionIterator) Next() bool {
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

	it.items = response.Functions
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *FunctionIterator) Take(size int64) ([]*functions.Function, error) {
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

	var result []*functions.Function

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionIterator) TakeAll() ([]*functions.Function, error) {
	return it.Take(0)
}

func (it *FunctionIterator) Value() *functions.Function {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionIterator) Error() error {
	return it.err
}

// ListAccessBindings implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListAccessBindings(ctx, in, opts...)
}

type FunctionAccessBindingsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *access.ListAccessBindingsRequest

	items []*access.AccessBinding
}

func (c *FunctionServiceClient) FunctionAccessBindingsIterator(ctx context.Context, req *access.ListAccessBindingsRequest, opts ...grpc.CallOption) *FunctionAccessBindingsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionAccessBindingsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionAccessBindingsIterator) Next() bool {
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

	response, err := it.client.ListAccessBindings(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.AccessBindings
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *FunctionAccessBindingsIterator) Take(size int64) ([]*access.AccessBinding, error) {
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

	var result []*access.AccessBinding

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionAccessBindingsIterator) TakeAll() ([]*access.AccessBinding, error) {
	return it.Take(0)
}

func (it *FunctionAccessBindingsIterator) Value() *access.AccessBinding {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionAccessBindingsIterator) Error() error {
	return it.err
}

// ListOperations implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListOperations(ctx context.Context, in *functions.ListFunctionOperationsRequest, opts ...grpc.CallOption) (*functions.ListFunctionOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListOperations(ctx, in, opts...)
}

type FunctionOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListFunctionOperationsRequest

	items []*operation.Operation
}

func (c *FunctionServiceClient) FunctionOperationsIterator(ctx context.Context, req *functions.ListFunctionOperationsRequest, opts ...grpc.CallOption) *FunctionOperationsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionOperationsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionOperationsIterator) Next() bool {
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

func (it *FunctionOperationsIterator) Take(size int64) ([]*operation.Operation, error) {
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

func (it *FunctionOperationsIterator) TakeAll() ([]*operation.Operation, error) {
	return it.Take(0)
}

func (it *FunctionOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionOperationsIterator) Error() error {
	return it.err
}

// ListRuntimes implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListRuntimes(ctx context.Context, in *functions.ListRuntimesRequest, opts ...grpc.CallOption) (*functions.ListRuntimesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListRuntimes(ctx, in, opts...)
}

type FunctionRuntimesIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListRuntimesRequest

	items []string
}

func (c *FunctionServiceClient) FunctionRuntimesIterator(ctx context.Context, req *functions.ListRuntimesRequest, opts ...grpc.CallOption) *FunctionRuntimesIterator {
	var pageSize int64
	const defaultPageSize = 1000

	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionRuntimesIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionRuntimesIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started {
		return false
	}
	it.started = true

	response, err := it.client.ListRuntimes(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Runtimes
	return len(it.items) > 0
}

func (it *FunctionRuntimesIterator) Take(size int64) ([]string, error) {
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

	var result []string

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionRuntimesIterator) TakeAll() ([]string, error) {
	return it.Take(0)
}

func (it *FunctionRuntimesIterator) Value() string {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionRuntimesIterator) Error() error {
	return it.err
}

// ListScalingPolicies implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListScalingPolicies(ctx context.Context, in *functions.ListScalingPoliciesRequest, opts ...grpc.CallOption) (*functions.ListScalingPoliciesResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListScalingPolicies(ctx, in, opts...)
}

type FunctionScalingPoliciesIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListScalingPoliciesRequest

	items []*functions.ScalingPolicy
}

func (c *FunctionServiceClient) FunctionScalingPoliciesIterator(ctx context.Context, req *functions.ListScalingPoliciesRequest, opts ...grpc.CallOption) *FunctionScalingPoliciesIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionScalingPoliciesIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionScalingPoliciesIterator) Next() bool {
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

	response, err := it.client.ListScalingPolicies(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.ScalingPolicies
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *FunctionScalingPoliciesIterator) Take(size int64) ([]*functions.ScalingPolicy, error) {
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

	var result []*functions.ScalingPolicy

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionScalingPoliciesIterator) TakeAll() ([]*functions.ScalingPolicy, error) {
	return it.Take(0)
}

func (it *FunctionScalingPoliciesIterator) Value() *functions.ScalingPolicy {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionScalingPoliciesIterator) Error() error {
	return it.err
}

// ListTagHistory implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListTagHistory(ctx context.Context, in *functions.ListFunctionTagHistoryRequest, opts ...grpc.CallOption) (*functions.ListFunctionTagHistoryResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListTagHistory(ctx, in, opts...)
}

type FunctionTagHistoryIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListFunctionTagHistoryRequest

	items []*functions.ListFunctionTagHistoryResponse_FunctionTagHistoryRecord
}

func (c *FunctionServiceClient) FunctionTagHistoryIterator(ctx context.Context, req *functions.ListFunctionTagHistoryRequest, opts ...grpc.CallOption) *FunctionTagHistoryIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionTagHistoryIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionTagHistoryIterator) Next() bool {
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

	response, err := it.client.ListTagHistory(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.FunctionTagHistoryRecord
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *FunctionTagHistoryIterator) Take(size int64) ([]*functions.ListFunctionTagHistoryResponse_FunctionTagHistoryRecord, error) {
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

	var result []*functions.ListFunctionTagHistoryResponse_FunctionTagHistoryRecord

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionTagHistoryIterator) TakeAll() ([]*functions.ListFunctionTagHistoryResponse_FunctionTagHistoryRecord, error) {
	return it.Take(0)
}

func (it *FunctionTagHistoryIterator) Value() *functions.ListFunctionTagHistoryResponse_FunctionTagHistoryRecord {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionTagHistoryIterator) Error() error {
	return it.err
}

// ListVersions implements functions.FunctionServiceClient
func (c *FunctionServiceClient) ListVersions(ctx context.Context, in *functions.ListFunctionsVersionsRequest, opts ...grpc.CallOption) (*functions.ListFunctionsVersionsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).ListVersions(ctx, in, opts...)
}

type FunctionVersionsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *FunctionServiceClient
	request *functions.ListFunctionsVersionsRequest

	items []*functions.Version
}

func (c *FunctionServiceClient) FunctionVersionsIterator(ctx context.Context, req *functions.ListFunctionsVersionsRequest, opts ...grpc.CallOption) *FunctionVersionsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &FunctionVersionsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *FunctionVersionsIterator) Next() bool {
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

	response, err := it.client.ListVersions(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Versions
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *FunctionVersionsIterator) Take(size int64) ([]*functions.Version, error) {
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

	var result []*functions.Version

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *FunctionVersionsIterator) TakeAll() ([]*functions.Version, error) {
	return it.Take(0)
}

func (it *FunctionVersionsIterator) Value() *functions.Version {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *FunctionVersionsIterator) Error() error {
	return it.err
}

// RemoveScalingPolicy implements functions.FunctionServiceClient
func (c *FunctionServiceClient) RemoveScalingPolicy(ctx context.Context, in *functions.RemoveScalingPolicyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).RemoveScalingPolicy(ctx, in, opts...)
}

// RemoveTag implements functions.FunctionServiceClient
func (c *FunctionServiceClient) RemoveTag(ctx context.Context, in *functions.RemoveFunctionTagRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).RemoveTag(ctx, in, opts...)
}

// SetAccessBindings implements functions.FunctionServiceClient
func (c *FunctionServiceClient) SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).SetAccessBindings(ctx, in, opts...)
}

// SetScalingPolicy implements functions.FunctionServiceClient
func (c *FunctionServiceClient) SetScalingPolicy(ctx context.Context, in *functions.SetScalingPolicyRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).SetScalingPolicy(ctx, in, opts...)
}

// SetTag implements functions.FunctionServiceClient
func (c *FunctionServiceClient) SetTag(ctx context.Context, in *functions.SetFunctionTagRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).SetTag(ctx, in, opts...)
}

// Update implements functions.FunctionServiceClient
func (c *FunctionServiceClient) Update(ctx context.Context, in *functions.UpdateFunctionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).Update(ctx, in, opts...)
}

// UpdateAccessBindings implements functions.FunctionServiceClient
func (c *FunctionServiceClient) UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return functions.NewFunctionServiceClient(conn).UpdateAccessBindings(ctx, in, opts...)
}