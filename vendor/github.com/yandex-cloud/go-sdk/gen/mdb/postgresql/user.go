// Code generated by sdkgen. DO NOT EDIT.

// nolint
package postgresql

import (
	"context"

	"google.golang.org/grpc"

	postgresql "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
)

//revive:disable

// UserServiceClient is a postgresql.UserServiceClient with
// lazy GRPC connection initialization.
type UserServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Create implements postgresql.UserServiceClient
func (c *UserServiceClient) Create(ctx context.Context, in *postgresql.CreateUserRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).Create(ctx, in, opts...)
}

// Delete implements postgresql.UserServiceClient
func (c *UserServiceClient) Delete(ctx context.Context, in *postgresql.DeleteUserRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).Delete(ctx, in, opts...)
}

// Get implements postgresql.UserServiceClient
func (c *UserServiceClient) Get(ctx context.Context, in *postgresql.GetUserRequest, opts ...grpc.CallOption) (*postgresql.User, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).Get(ctx, in, opts...)
}

// GrantPermission implements postgresql.UserServiceClient
func (c *UserServiceClient) GrantPermission(ctx context.Context, in *postgresql.GrantUserPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).GrantPermission(ctx, in, opts...)
}

// List implements postgresql.UserServiceClient
func (c *UserServiceClient) List(ctx context.Context, in *postgresql.ListUsersRequest, opts ...grpc.CallOption) (*postgresql.ListUsersResponse, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).List(ctx, in, opts...)
}

type UserIterator struct {
	ctx  context.Context
	opts []grpc.CallOption

	err           error
	started       bool
	requestedSize int64
	pageSize      int64

	client  *UserServiceClient
	request *postgresql.ListUsersRequest

	items []*postgresql.User
}

func (c *UserServiceClient) UserIterator(ctx context.Context, req *postgresql.ListUsersRequest, opts ...grpc.CallOption) *UserIterator {
	var pageSize int64
	const defaultPageSize = 1000
	pageSize = req.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	}
	return &UserIterator{
		ctx:      ctx,
		opts:     opts,
		client:   c,
		request:  req,
		pageSize: pageSize,
	}
}

func (it *UserIterator) Next() bool {
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

	it.items = response.Users
	it.request.PageToken = response.NextPageToken
	return len(it.items) > 0
}

func (it *UserIterator) Take(size int64) ([]*postgresql.User, error) {
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

	var result []*postgresql.User

	for it.requestedSize > 0 && it.Next() {
		it.requestedSize--
		result = append(result, it.Value())
	}

	if it.err != nil {
		return nil, it.err
	}

	return result, nil
}

func (it *UserIterator) TakeAll() ([]*postgresql.User, error) {
	return it.Take(0)
}

func (it *UserIterator) Value() *postgresql.User {
	if len(it.items) == 0 {
		panic("calling Value on empty iterator")
	}
	return it.items[0]
}

func (it *UserIterator) Error() error {
	return it.err
}

// RevokePermission implements postgresql.UserServiceClient
func (c *UserServiceClient) RevokePermission(ctx context.Context, in *postgresql.RevokeUserPermissionRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).RevokePermission(ctx, in, opts...)
}

// Update implements postgresql.UserServiceClient
func (c *UserServiceClient) Update(ctx context.Context, in *postgresql.UpdateUserRequest, opts ...grpc.CallOption) (*operation.Operation, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return postgresql.NewUserServiceClient(conn).Update(ctx, in, opts...)
}
