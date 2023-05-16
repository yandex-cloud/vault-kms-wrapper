package yandexcloudkms

import (
	"context"
	"encoding/base64"
	"fmt"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/kms/v1"
	"google.golang.org/grpc"
	"os"
	"reflect"
	"testing"
)

const (
	text       = "foo"
	versionID1 = "version-id-1"
	versionID2 = "version-id-2"
)

func TestYandexCloudKMSWrapper(t *testing.T) {
	wrapper := NewWrapper()
	wrapper.setTestClient(t, versionID1)

	wrapper.setConfigFail(t)

	setEnvKey(t)
	defer func() {
		unsetEnvKey(t)
	}()

	wrapper.setConfigSuccess(t)
}

func TestYandexCloudKMSWrapper_Lifecycle(t *testing.T) {
	wrapper := NewWrapper()
	wrapper.setTestClient(t, versionID1)

	setEnvKey(t)
	defer func() {
		unsetEnvKey(t)
	}()

	wrapper.setConfigSuccess(t)

	// Test Encrypt and Decrypt calls
	encryptedBlobInfo := wrapper.encrypt(t, text)

	decrypted := wrapper.decrypt(t, encryptedBlobInfo)

	if !reflect.DeepEqual(decrypted, text) {
		t.Fatalf("expected %s, got %s", text, decrypted)
	}
}

func TestYandexCloudKMSWrapper_KeyRotation(t *testing.T) {
	wrapper := NewWrapper()
	client := wrapper.setTestClient(t, versionID1)

	setEnvKey(t)
	defer func() {
		unsetEnvKey(t)
	}()
	wrapper.setConfigSuccess(t)

	if !reflect.DeepEqual(wrapper.versionId(), versionID1) {
		t.Fatalf("expected %s, got %s", versionID1, wrapper.versionId())
	}

	client.rotateKey(versionID2)
	if !reflect.DeepEqual(wrapper.versionId(), versionID1) {
		t.Fatalf("expected %s, got %s", versionID1, wrapper.versionId())
	}

	// Only Encrypt calls update wrapper.currentVersionID
	wrapper.encrypt(t, text)
	if !reflect.DeepEqual(wrapper.versionId(), versionID2) {
		t.Fatalf("expected %s, got %s", versionID2, wrapper.versionId())
	}
}

func (wrapper *Wrapper) encrypt(t *testing.T, text string) *wrapping.BlobInfo {
	plaintext := []byte(text)
	encryptedBlobInfo, err := wrapper.Encrypt(context.Background(), plaintext, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	return encryptedBlobInfo
}

func (wrapper *Wrapper) decrypt(t *testing.T, encryptedBlobInfo *wrapping.BlobInfo) string {
	decrypted, err := wrapper.Decrypt(context.Background(), encryptedBlobInfo, nil)
	if err != nil {
		t.Fatalf("err: %s", err.Error())
	}

	return string(decrypted)
}

// Mock implementation of kms.SymmetricCryptoServiceClient
type mockSymmetricCryptoServiceClient struct {
	primaryVersionID string
}

func (m *mockSymmetricCryptoServiceClient) Encrypt(_ context.Context, in *kms.SymmetricEncryptRequest, _ ...grpc.CallOption) (*kms.SymmetricEncryptResponse, error) {
	encoded := base64.StdEncoding.EncodeToString(in.Plaintext)

	return &kms.SymmetricEncryptResponse{
		KeyId:      in.KeyId,
		VersionId:  m.primaryVersionID,
		Ciphertext: []byte(encoded),
	}, nil
}

func (m *mockSymmetricCryptoServiceClient) Decrypt(_ context.Context, in *kms.SymmetricDecryptRequest, _ ...grpc.CallOption) (*kms.SymmetricDecryptResponse, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(in.Ciphertext))
	if err != nil {
		return nil, err
	}

	return &kms.SymmetricDecryptResponse{
		KeyId:     in.KeyId,
		VersionId: m.primaryVersionID,
		Plaintext: decoded,
	}, nil
}

func (m *mockSymmetricCryptoServiceClient) ReEncrypt(_ context.Context, _ *kms.SymmetricReEncryptRequest, _ ...grpc.CallOption) (*kms.SymmetricReEncryptResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSymmetricCryptoServiceClient) GenerateDataKey(_ context.Context, _ *kms.GenerateDataKeyRequest, _ ...grpc.CallOption) (*kms.GenerateDataKeyResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSymmetricCryptoServiceClient) rotateKey(primaryVersionID string) {
	m.primaryVersionID = primaryVersionID
}

func (wrapper *Wrapper) setConfigSuccess(t *testing.T) {
	if _, err := wrapper.SetConfig(nil); err != nil {
		t.Fatal(err)
	}
}

func (wrapper *Wrapper) setConfigFail(t *testing.T) {
	if _, err := wrapper.SetConfig(nil); err == nil {
		t.Fatal(err)
	}
}

func (wrapper *Wrapper) setTestClient(t *testing.T, versionId string) *mockSymmetricCryptoServiceClient {
	client := &mockSymmetricCryptoServiceClient{primaryVersionID: versionId}
	if err := wrapper.setClient(client); err != nil {
		t.Fatal(err)
	}
	return client
}

func setEnvKey(t *testing.T) {
	if err := os.Setenv(EnvYandexCloudKMSKeyID, "key-id"); err != nil {
		t.Fatal(err)
	}
}

func unsetEnvKey(t *testing.T) {
	if err := os.Unsetenv(EnvYandexCloudKMSKeyID); err != nil {
		t.Fatal(err)
	}
}
