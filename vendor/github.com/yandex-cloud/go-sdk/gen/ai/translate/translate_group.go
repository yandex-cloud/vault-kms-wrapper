// Code generated by sdkgen. DO NOT EDIT.

package translate

import (
	"context"

	"google.golang.org/grpc"
)

// Translate provides access to "translate" component of Yandex.Cloud
type Translate struct {
	getConn func(ctx context.Context) (*grpc.ClientConn, error)
}

// NewTranslate creates instance of Translate
func NewTranslate(g func(ctx context.Context) (*grpc.ClientConn, error)) *Translate {
	return &Translate{g}
}

// Translation gets TranslationService client
func (t *Translate) Translation() *TranslationServiceClient {
	return &TranslationServiceClient{getConn: t.getConn}
}
