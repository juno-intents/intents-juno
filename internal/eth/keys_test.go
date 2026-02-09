package eth

import (
	"errors"
	"testing"
)

func TestParsePrivateKeysHexList_AcceptsCommaSeparated(t *testing.T) {
	keys, err := ParsePrivateKeysHexList("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a, 0x6c875d0e7f3d0d840e4f1a400a54c3c4d5ef0e8f55d8aee0b1b1f0c0a8f6c1d1")
	if err != nil {
		t.Fatalf("ParsePrivateKeysHexList: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys: got %d want %d", len(keys), 2)
	}
}

func TestParsePrivateKeysHexList_RejectsInvalidKey(t *testing.T) {
	_, err := ParsePrivateKeysHexList("0x1234")
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey, got %v", err)
	}
}
