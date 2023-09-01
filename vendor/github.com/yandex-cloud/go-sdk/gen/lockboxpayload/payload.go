// Code generated by sdkgen. DO NOT EDIT.

// nolint
package lockbox

import (
	"context"

	"google.golang.org/grpc"

	lockbox "github.com/yandex-cloud/go-genproto/yandex/cloud/lockbox/v1"
)

//revive:disable

// PayloadServiceClient is a lockbox.PayloadServiceClient with
// lazy GRPC connection initialization.
type PayloadServiceClient struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// Get implements lockbox.PayloadServiceClient
func (c *PayloadServiceClient) Get(ctx context.Context, in *lockbox.GetPayloadRequest, opts ...grpc.CallOption) (*lockbox.Payload, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return lockbox.NewPayloadServiceClient(conn).Get(ctx, in, opts...)
}