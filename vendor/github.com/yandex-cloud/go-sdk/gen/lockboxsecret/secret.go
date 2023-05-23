// Code generated by sdkgen. DO NOT EDIT.

// nolint
package lockbox

import (
	"context"

	"google.golang.org/grpc"

	"github.com/yandex-cloud/go-genproto/yandex/cloud/access"
	lockbox "github.com/yandex-cloud/go-genproto/yandex/cloud/lockbox/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// SecretServiceClient is a lockbox.SecretServiceClient with
// lazy GRPC connection initialization.
type SecretServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Activate implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Activate(ctx context.Context, in *lockbox.ActivateSecretRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Activate(ctx, in, opts...)
}

// AddVersion implements lockbox.SecretServiceClient
func (c *SecretServiceClient) AddVersion(ctx context.Context, in *lockbox.AddVersionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).AddVersion(ctx, in, opts...)
}

// CancelVersionDestruction implements lockbox.SecretServiceClient
func (c *SecretServiceClient) CancelVersionDestruction(ctx context.Context, in *lockbox.CancelVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).CancelVersionDestruction(ctx, in, opts...)
}

// Create implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Create(ctx context.Context, in *lockbox.CreateSecretRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Create(ctx, in, opts...)
}

// Deactivate implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Deactivate(ctx context.Context, in *lockbox.DeactivateSecretRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Deactivate(ctx, in, opts...)
}

// Delete implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Delete(ctx context.Context, in *lockbox.DeleteSecretRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Get(ctx context.Context, in *lockbox.GetSecretRequest, opts ...grpc.CallOption) (*lockbox.Secret, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Get(ctx, in, opts...)
}

// List implements lockbox.SecretServiceClient
func (c *SecretServiceClient) List(ctx context.Context, in *lockbox.ListSecretsRequest, opts ...grpc.CallOption) (*lockbox.ListSecretsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).List(ctx, in, opts...)
}

type SecretIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *SecretServiceClient
	request *lockbox.ListSecretsRequest

	items []*lockbox.Secret
}

func (c *SecretServiceClient) SecretIterator(ctx context.Context, req *lockbox.ListSecretsRequest, opts ...grpc.CallOption) *SecretIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &SecretIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *SecretIterator) Next() bool {
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

	it.items = response.Secrets
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *SecretIterator) Take(size int64) ([]*lockbox.Secret, error) {
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

	var result []*lockbox.Secret

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *SecretIterator) TakeAll() ([]*lockbox.Secret, error) {
	return it.Take(0)
}

func (it *SecretIterator) Value() *lockbox.Secret {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *SecretIterator) Error() error {
	return it.err
}

// ListAccessBindings implements lockbox.SecretServiceClient
func (c *SecretServiceClient) ListAccessBindings(ctx context.Context, in *access.ListAccessBindingsRequest, opts ...grpc.CallOption) (*access.ListAccessBindingsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).ListAccessBindings(ctx, in, opts...)
}

type SecretAccessBindingsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *SecretServiceClient
	request *access.ListAccessBindingsRequest

	items []*access.AccessBinding
}

func (c *SecretServiceClient) SecretAccessBindingsIterator(ctx context.Context, req *access.ListAccessBindingsRequest, opts ...grpc.CallOption) *SecretAccessBindingsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &SecretAccessBindingsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *SecretAccessBindingsIterator) Next() bool {
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

func (it *SecretAccessBindingsIterator) Take(size int64) ([]*access.AccessBinding, error) {
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

func (it *SecretAccessBindingsIterator) TakeAll() ([]*access.AccessBinding, error) {
	return it.Take(0)
}

func (it *SecretAccessBindingsIterator) Value() *access.AccessBinding {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *SecretAccessBindingsIterator) Error() error {
	return it.err
}

// ListOperations implements lockbox.SecretServiceClient
func (c *SecretServiceClient) ListOperations(ctx context.Context, in *lockbox.ListSecretOperationsRequest, opts ...grpc.CallOption) (*lockbox.ListSecretOperationsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).ListOperations(ctx, in, opts...)
}

type SecretOperationsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *SecretServiceClient
	request *lockbox.ListSecretOperationsRequest

	items []*operation.Operation
}

func (c *SecretServiceClient) SecretOperationsIterator(ctx context.Context, req *lockbox.ListSecretOperationsRequest, opts ...grpc.CallOption) *SecretOperationsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &SecretOperationsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *SecretOperationsIterator) Next() bool {
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

func (it *SecretOperationsIterator) Take(size int64) ([]*operation.Operation, error) {
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

func (it *SecretOperationsIterator) TakeAll() ([]*operation.Operation, error) {
	return it.Take(0)
}

func (it *SecretOperationsIterator) Value() *operation.Operation {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *SecretOperationsIterator) Error() error {
	return it.err
}

// ListVersions implements lockbox.SecretServiceClient
func (c *SecretServiceClient) ListVersions(ctx context.Context, in *lockbox.ListVersionsRequest, opts ...grpc.CallOption) (*lockbox.ListVersionsResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).ListVersions(ctx, in, opts...)
}

type SecretVersionsIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *SecretServiceClient
	request *lockbox.ListVersionsRequest

	items []*lockbox.Version
}

func (c *SecretServiceClient) SecretVersionsIterator(ctx context.Context, req *lockbox.ListVersionsRequest, opts ...grpc.CallOption) *SecretVersionsIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &SecretVersionsIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *SecretVersionsIterator) Next() bool {
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

func (it *SecretVersionsIterator) Take(size int64) ([]*lockbox.Version, error) {
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

	var result []*lockbox.Version

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *SecretVersionsIterator) TakeAll() ([]*lockbox.Version, error) {
	return it.Take(0)
}

func (it *SecretVersionsIterator) Value() *lockbox.Version {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *SecretVersionsIterator) Error() error {
	return it.err
}

// ScheduleVersionDestruction implements lockbox.SecretServiceClient
func (c *SecretServiceClient) ScheduleVersionDestruction(ctx context.Context, in *lockbox.ScheduleVersionDestructionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).ScheduleVersionDestruction(ctx, in, opts...)
}

// SetAccessBindings implements lockbox.SecretServiceClient
func (c *SecretServiceClient) SetAccessBindings(ctx context.Context, in *access.SetAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).SetAccessBindings(ctx, in, opts...)
}

// Update implements lockbox.SecretServiceClient
func (c *SecretServiceClient) Update(ctx context.Context, in *lockbox.UpdateSecretRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).Update(ctx, in, opts...)
}

// UpdateAccessBindings implements lockbox.SecretServiceClient
func (c *SecretServiceClient) UpdateAccessBindings(ctx context.Context, in *access.UpdateAccessBindingsRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewSecretServiceClient(conn).UpdateAccessBindings(ctx, in, opts...)
}
