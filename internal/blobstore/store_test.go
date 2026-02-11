package blobstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "memory",
			cfg: Config{
				Driver: DriverMemory,
			},
		},
		{
			name: "unsupported driver",
			cfg: Config{
				Driver: "gcs",
			},
			wantErr: true,
		},
		{
			name: "s3 missing bucket",
			cfg: Config{
				Driver:   DriverS3,
				S3Client: &fakeS3Client{},
			},
			wantErr: true,
		},
		{
			name: "s3 missing client",
			cfg: Config{
				Driver: DriverS3,
				Bucket: "juno-artifacts",
			},
			wantErr: true,
		},
		{
			name: "default driver is s3",
			cfg: Config{
				Bucket:   "juno-artifacts",
				S3Client: &fakeS3Client{},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, err := New(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("expected ErrInvalidConfig, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if store == nil {
				t.Fatalf("New returned nil store")
			}
		})
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store, err := New(Config{
		Driver: DriverMemory,
		Prefix: "operator-a/",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload := []byte(`{"version":"txplan.v0","batch":"b1"}`)
	if err := store.Put(context.Background(), "/withdrawals/b1/txplan.json", payload, PutOptions{
		ContentType: "application/json",
		Metadata: map[string]string{
			"artifact-type": "txplan",
			"batch-id":      "b1",
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err := store.Exists(context.Background(), "withdrawals/b1/txplan.json")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Fatalf("Exists returned false for persisted key")
	}

	obj, err := store.Get(context.Background(), "withdrawals/b1/txplan.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := obj.Key, "withdrawals/b1/txplan.json"; got != want {
		t.Fatalf("key mismatch: got %q want %q", got, want)
	}
	if !bytes.Equal(obj.Data, payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(obj.Data), string(payload))
	}
	if got, want := obj.ContentType, "application/json"; got != want {
		t.Fatalf("content type mismatch: got %q want %q", got, want)
	}
	if got, want := obj.Metadata["artifact-type"], "txplan"; got != want {
		t.Fatalf("metadata mismatch: got %q want %q", got, want)
	}

	// Ensure returned slices/maps are defensive copies.
	obj.Data[0] = 'X'
	obj.Metadata["artifact-type"] = "changed"
	reload, err := store.Get(context.Background(), "withdrawals/b1/txplan.json")
	if err != nil {
		t.Fatalf("Get reload: %v", err)
	}
	if reload.Data[0] != '{' {
		t.Fatalf("expected stored payload to remain unchanged")
	}
	if got, want := reload.Metadata["artifact-type"], "txplan"; got != want {
		t.Fatalf("expected stored metadata to remain unchanged; got %q", got)
	}

	if err := store.Delete(context.Background(), "withdrawals/b1/txplan.json"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ok, err = store.Exists(context.Background(), "withdrawals/b1/txplan.json")
	if err != nil {
		t.Fatalf("Exists after delete: %v", err)
	}
	if ok {
		t.Fatalf("expected key to be deleted")
	}

	_, err = store.Get(context.Background(), "withdrawals/b1/txplan.json")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreRejectsInvalidKeys(t *testing.T) {
	t.Parallel()

	store, err := New(Config{Driver: DriverMemory})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []string{"", "   ", "\x00bad", "\nnewline"}
	for _, key := range tests {
		key := key
		t.Run(strings.ReplaceAll(key, "\x00", "nul"), func(t *testing.T) {
			t.Parallel()
			if err := store.Put(context.Background(), key, []byte("x"), PutOptions{}); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("Put(%q): expected ErrInvalidKey, got %v", key, err)
			}
			_, err := store.Get(context.Background(), key)
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("Get(%q): expected ErrInvalidKey, got %v", key, err)
			}
		})
	}
}

func TestS3StorePutGetExistsAndDelete(t *testing.T) {
	t.Parallel()

	client := &fakeS3Client{}
	store, err := New(Config{
		Driver:     DriverS3,
		Bucket:     "juno-artifacts",
		Prefix:     "operator-1",
		MaxGetSize: 4 << 10,
		S3Client:   client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	client.putFn = func(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
		if got, want := aws.ToString(in.Bucket), "juno-artifacts"; got != want {
			t.Fatalf("bucket mismatch: got %q want %q", got, want)
		}
		if got, want := aws.ToString(in.Key), "operator-1/withdrawals/b1/signed.tx"; got != want {
			t.Fatalf("key mismatch: got %q want %q", got, want)
		}
		if got, want := aws.ToString(in.ContentType), "application/octet-stream"; got != want {
			t.Fatalf("content type mismatch: got %q want %q", got, want)
		}
		if got, want := in.Metadata["artifact-type"], "signed_tx"; got != want {
			t.Fatalf("metadata mismatch: got %q want %q", got, want)
		}
		return &s3.PutObjectOutput{}, nil
	}
	client.getFn = func(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
		if got, want := aws.ToString(in.Key), "operator-1/withdrawals/b1/signed.tx"; got != want {
			t.Fatalf("get key mismatch: got %q want %q", got, want)
		}
		return &s3.GetObjectOutput{
			Body:        io.NopCloser(strings.NewReader("signedtx")),
			ContentType: aws.String("application/octet-stream"),
			Metadata: map[string]string{
				"artifact-type": "signed_tx",
			},
			ETag: aws.String(`"abc123"`),
		}, nil
	}
	client.headFn = func(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
		if got, want := aws.ToString(in.Key), "operator-1/withdrawals/b1/signed.tx"; got != want {
			t.Fatalf("head key mismatch: got %q want %q", got, want)
		}
		return &s3.HeadObjectOutput{}, nil
	}
	client.deleteFn = func(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
		if got, want := aws.ToString(in.Key), "operator-1/withdrawals/b1/signed.tx"; got != want {
			t.Fatalf("delete key mismatch: got %q want %q", got, want)
		}
		return &s3.DeleteObjectOutput{}, nil
	}

	if err := store.Put(context.Background(), "withdrawals/b1/signed.tx", []byte("signedtx"), PutOptions{
		ContentType: "application/octet-stream",
		Metadata: map[string]string{
			"artifact-type": "signed_tx",
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	obj, err := store.Get(context.Background(), "withdrawals/b1/signed.tx")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := string(obj.Data), "signedtx"; got != want {
		t.Fatalf("data mismatch: got %q want %q", got, want)
	}
	if got, want := obj.Metadata["artifact-type"], "signed_tx"; got != want {
		t.Fatalf("metadata mismatch: got %q want %q", got, want)
	}

	ok, err := store.Exists(context.Background(), "withdrawals/b1/signed.tx")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Fatalf("Exists returned false for present object")
	}

	if err := store.Delete(context.Background(), "withdrawals/b1/signed.tx"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestS3StoreMapsNotFound(t *testing.T) {
	t.Parallel()

	client := &fakeS3Client{
		getFn: func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
			return nil, fakeAPIError{code: "NoSuchKey", msg: "missing"}
		},
		headFn: func(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
			return nil, fakeAPIError{code: "NotFound", msg: "missing"}
		},
	}

	store, err := New(Config{
		Driver:   DriverS3,
		Bucket:   "juno-artifacts",
		S3Client: client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = store.Get(context.Background(), "withdrawals/b2/txplan.json")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound from Get, got %v", err)
	}

	ok, err := store.Exists(context.Background(), "withdrawals/b2/txplan.json")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Fatalf("Exists returned true for missing key")
	}
}

func TestS3StoreMaxGetSize(t *testing.T) {
	t.Parallel()

	client := &fakeS3Client{
		getFn: func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{
				Body: io.NopCloser(strings.NewReader("this payload is too large")),
			}, nil
		},
	}

	store, err := New(Config{
		Driver:     DriverS3,
		Bucket:     "juno-artifacts",
		S3Client:   client,
		MaxGetSize: 8,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = store.Get(context.Background(), "withdrawals/b3/txplan.json")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

type fakeS3Client struct {
	putFn    func(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	getFn    func(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	deleteFn func(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	headFn   func(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

func (f *fakeS3Client) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.putFn == nil {
		return &s3.PutObjectOutput{}, nil
	}
	return f.putFn(ctx, in, opts...)
}

func (f *fakeS3Client) GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.getFn == nil {
		return nil, errors.New("unexpected GetObject call")
	}
	return f.getFn(ctx, in, opts...)
}

func (f *fakeS3Client) DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if f.deleteFn == nil {
		return &s3.DeleteObjectOutput{}, nil
	}
	return f.deleteFn(ctx, in, opts...)
}

func (f *fakeS3Client) HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if f.headFn == nil {
		return &s3.HeadObjectOutput{}, nil
	}
	return f.headFn(ctx, in, opts...)
}

type fakeAPIError struct {
	code string
	msg  string
}

func (f fakeAPIError) ErrorCode() string {
	return f.code
}

func (f fakeAPIError) ErrorMessage() string {
	return f.msg
}

func (f fakeAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}

func (f fakeAPIError) Error() string {
	return f.code + ": " + f.msg
}
