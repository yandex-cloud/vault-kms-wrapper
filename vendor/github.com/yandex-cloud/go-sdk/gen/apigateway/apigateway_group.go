// Code generated by sdkgen. DO NOT EDIT.

package apigateway

import (
	"context"

	"google.golang.org/grpc"
)

// Apigateway provides access to "apigateway" component of Yandex.Cloud
type Apigateway struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// NewApigateway creates instance of Apigateway
func NewApigateway(g func(ctx context.Context) (*grpc.ClientConn, error)) *Apigateway {
	return &Apigateway{g}
}

// ApiGateway gets ApiGatewayService client
func (a *Apigateway) ApiGateway() *ApiGatewayServiceClient {
	return &ApiGatewayServiceClient{getConn: a.getConn}
}