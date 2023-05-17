// Code generated by sdkgen. DO NOT EDIT.

// nolint
package elasticsearch

import (
	"context"

	"google.golang.org/grpc"

	elasticsearch "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/elasticsearch/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// AuthServiceClient is a elasticsearch.AuthServiceClient with
// lazy GRPC connection initialization.
type AuthServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// AddProviders implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) AddProviders(ctx context.Context, in *elasticsearch.AddAuthProvidersRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).AddProviders(ctx, in, opts...)
}

// DeleteProvider implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) DeleteProvider(ctx context.Context, in *elasticsearch.DeleteAuthProviderRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).DeleteProvider(ctx, in, opts...)
}

// DeleteProviders implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) DeleteProviders(ctx context.Context, in *elasticsearch.DeleteAuthProvidersRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).DeleteProviders(ctx, in, opts...)
}

// GetProvider implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) GetProvider(ctx context.Context, in *elasticsearch.GetAuthProviderRequest, opts ...grpc.CallOption) (*elasticsearch.AuthProvider, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).GetProvider(ctx, in, opts...)
}

// ListProviders implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) ListProviders(ctx context.Context, in *elasticsearch.ListAuthProvidersRequest, opts ...grpc.CallOption) (*elasticsearch.ListAuthProvidersResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).ListProviders(ctx, in, opts...)
}

type AuthProvidersIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *AuthServiceClient
	request *elasticsearch.ListAuthProvidersRequest

	items []*elasticsearch.AuthProvider
}

func (c *AuthServiceClient) AuthProvidersIterator(ctx context.Context, req *elasticsearch.ListAuthProvidersRequest, opts ...grpc.CallOption) *AuthProvidersIterator {
	var pageSize int64
	const defaultPageSize = 1000

	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &AuthProvidersIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *AuthProvidersIterator) Next() bool {
	if it.err != nil {
		return false
	}
	if len(it.items) > 1 {
		it.items[0] = nil
		it.items = it.items[1:]
		return true
	}
	it.items = nil // consume last item, if any

	if it.started {
		return false
	}
	it.started = true

	response, err := it.client.ListProviders(it.ctx, it.request, it.opts...)
	it.err = err
	if err != nil {
		return false
	}

	it.items = response.Providers
	return len(it.items) > 0
}

func (it *AuthProvidersIterator) Take(size int64) ([]*elasticsearch.AuthProvider, error) {
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

	var result []*elasticsearch.AuthProvider

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *AuthProvidersIterator) TakeAll() ([]*elasticsearch.AuthProvider, error) {
	return it.Take(0)
}

func (it *AuthProvidersIterator) Value() *elasticsearch.AuthProvider {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *AuthProvidersIterator) Error() error {
	return it.err
}

// UpdateProvider implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) UpdateProvider(ctx context.Context, in *elasticsearch.UpdateAuthProviderRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).UpdateProvider(ctx, in, opts...)
}

// UpdateProviders implements elasticsearch.AuthServiceClient
func (c *AuthServiceClient) UpdateProviders(ctx context.Context, in *elasticsearch.UpdateAuthProvidersRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return elasticsearch.NewAuthServiceClient(conn).UpdateProviders(ctx, in, opts...)
}
