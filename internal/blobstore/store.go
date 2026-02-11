package blobstore

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

const (
	DriverS3     = "s3"
	DriverMemory = "memory"

	defaultMaxGetSize int64 = 16 << 20
)

var (
	ErrInvalidConfig = errors.New("blobstore: invalid config")
	ErrInvalidKey    = errors.New("blobstore: invalid key")
	ErrNotFound      = errors.New("blobstore: not found")
	ErrTooLarge      = errors.New("blobstore: object too large")
)

// Store provides durable blob persistence for artifact payloads.
type Store interface {
	Put(ctx context.Context, key string, payload []byte, opts PutOptions) error
	Get(ctx context.Context, key string) (Object, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}

type PutOptions struct {
	ContentType string
	Metadata    map[string]string
}

type Object struct {
	Key          string
	Data         []byte
	ContentType  string
	Metadata     map[string]string
	ETag         string
	LastModified time.Time
}

type Config struct {
	Driver string
	Prefix string

	// MaxGetSize bounds bytes returned by Get. Defaults to 16 MiB when <= 0.
	MaxGetSize int64

	// S3 fields.
	Bucket   string
	S3Client S3Client
}

type S3Client interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

func New(cfg Config) (Store, error) {
	switch normalizeDriver(cfg.Driver) {
	case DriverMemory:
		return newMemoryStore(cfg.Prefix), nil
	case DriverS3:
		return newS3Store(cfg)
	default:
		return nil, fmt.Errorf("%w: unsupported driver %q", ErrInvalidConfig, cfg.Driver)
	}
}

func normalizeDriver(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return DriverS3
	}
	return v
}

func normalizeLogicalKey(key string) (string, error) {
	if key != strings.TrimSpace(key) {
		return "", fmt.Errorf("%w: key has leading or trailing whitespace", ErrInvalidKey)
	}
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", fmt.Errorf("%w: empty key", ErrInvalidKey)
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: key contains control characters", ErrInvalidKey)
		}
	}
	return key, nil
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	return strings.Trim(prefix, "/")
}

func joinPrefix(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

func cloneBytes(v []byte) []byte {
	if v == nil {
		return nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

func cloneMetadata(v map[string]string) map[string]string {
	if len(v) == 0 {
		return nil
	}
	out := make(map[string]string, len(v))
	for k, val := range v {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(val)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type memoryStore struct {
	mu      sync.RWMutex
	prefix  string
	objects map[string]memoryObject
}

type memoryObject struct {
	data        []byte
	contentType string
	metadata    map[string]string
	etag        string
	updatedAt   time.Time
}

func newMemoryStore(prefix string) Store {
	return &memoryStore{
		prefix:  normalizePrefix(prefix),
		objects: make(map[string]memoryObject),
	}
}

func (m *memoryStore) Put(_ context.Context, key string, payload []byte, opts PutOptions) error {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(m.prefix, logicalKey)

	hasher := md5.Sum(payload)
	m.mu.Lock()
	m.objects[fullKey] = memoryObject{
		data:        cloneBytes(payload),
		contentType: strings.TrimSpace(opts.ContentType),
		metadata:    cloneMetadata(opts.Metadata),
		etag:        hex.EncodeToString(hasher[:]),
		updatedAt:   time.Now().UTC(),
	}
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) Get(_ context.Context, key string) (Object, error) {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return Object{}, err
	}
	fullKey := joinPrefix(m.prefix, logicalKey)

	m.mu.RLock()
	obj, ok := m.objects[fullKey]
	m.mu.RUnlock()
	if !ok {
		return Object{}, fmt.Errorf("%w: %s", ErrNotFound, logicalKey)
	}
	return Object{
		Key:          logicalKey,
		Data:         cloneBytes(obj.data),
		ContentType:  obj.contentType,
		Metadata:     cloneMetadata(obj.metadata),
		ETag:         obj.etag,
		LastModified: obj.updatedAt,
	}, nil
}

func (m *memoryStore) Delete(_ context.Context, key string) error {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(m.prefix, logicalKey)

	m.mu.Lock()
	delete(m.objects, fullKey)
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) Exists(_ context.Context, key string) (bool, error) {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return false, err
	}
	fullKey := joinPrefix(m.prefix, logicalKey)

	m.mu.RLock()
	_, ok := m.objects[fullKey]
	m.mu.RUnlock()
	return ok, nil
}

type s3Store struct {
	client     S3Client
	bucket     string
	prefix     string
	maxGetSize int64
}

func newS3Store(cfg Config) (Store, error) {
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, fmt.Errorf("%w: s3 bucket is required", ErrInvalidConfig)
	}
	if cfg.S3Client == nil {
		return nil, fmt.Errorf("%w: s3 client is required", ErrInvalidConfig)
	}

	maxGet := cfg.MaxGetSize
	if maxGet <= 0 {
		maxGet = defaultMaxGetSize
	}

	return &s3Store{
		client:     cfg.S3Client,
		bucket:     bucket,
		prefix:     normalizePrefix(cfg.Prefix),
		maxGetSize: maxGet,
	}, nil
}

func (s *s3Store) Put(ctx context.Context, key string, payload []byte, opts PutOptions) error {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(s.prefix, logicalKey)

	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
		Body:   bytes.NewReader(payload),
	}
	if ct := strings.TrimSpace(opts.ContentType); ct != "" {
		input.ContentType = aws.String(ct)
	}
	if meta := cloneMetadata(opts.Metadata); len(meta) > 0 {
		input.Metadata = meta
	}

	if _, err := s.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("blobstore/s3: put %q: %w", logicalKey, err)
	}
	return nil
}

func (s *s3Store) Get(ctx context.Context, key string) (Object, error) {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return Object{}, err
	}
	fullKey := joinPrefix(s.prefix, logicalKey)

	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		if isNotFound(err) {
			return Object{}, fmt.Errorf("%w: %s", ErrNotFound, logicalKey)
		}
		return Object{}, fmt.Errorf("blobstore/s3: get %q: %w", logicalKey, err)
	}
	defer func() { _ = out.Body.Close() }()

	limited := io.LimitReader(out.Body, s.maxGetSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Object{}, fmt.Errorf("blobstore/s3: read %q: %w", logicalKey, err)
	}
	if int64(len(data)) > s.maxGetSize {
		return Object{}, fmt.Errorf("%w: key %q exceeds max %d bytes", ErrTooLarge, logicalKey, s.maxGetSize)
	}

	return Object{
		Key:          logicalKey,
		Data:         data,
		ContentType:  aws.ToString(out.ContentType),
		Metadata:     cloneMetadata(out.Metadata),
		ETag:         strings.Trim(aws.ToString(out.ETag), `"`),
		LastModified: aws.ToTime(out.LastModified),
	}, nil
}

func (s *s3Store) Delete(ctx context.Context, key string) error {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return err
	}
	fullKey := joinPrefix(s.prefix, logicalKey)

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("blobstore/s3: delete %q: %w", logicalKey, err)
	}
	return nil
}

func (s *s3Store) Exists(ctx context.Context, key string) (bool, error) {
	logicalKey, err := normalizeLogicalKey(key)
	if err != nil {
		return false, err
	}
	fullKey := joinPrefix(s.prefix, logicalKey)

	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("blobstore/s3: head %q: %w", logicalKey, err)
	}
	return true, nil
}

func isNotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "NoSuchKey", "NotFound", "404":
		return true
	default:
		return false
	}
}
