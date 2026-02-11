package checkpoint

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrInvalidQuorumConfig  = errors.New("checkpoint: invalid quorum config")
	ErrInsufficientSignatures = errors.New("checkpoint: insufficient signatures")
	ErrUnsortedSignatures   = errors.New("checkpoint: signatures not sorted or unique")
	ErrUnknownSigner        = errors.New("checkpoint: unknown signer")
)

type QuorumVerifier struct {
	operators map[common.Address]struct{}
	threshold int
}

func NewQuorumVerifier(operators []common.Address, threshold int) (*QuorumVerifier, error) {
	if threshold <= 0 {
		return nil, fmt.Errorf("%w: threshold must be > 0", ErrInvalidQuorumConfig)
	}
	if len(operators) == 0 {
		return nil, fmt.Errorf("%w: operators must be non-empty", ErrInvalidQuorumConfig)
	}

	ops := make(map[common.Address]struct{}, len(operators))
	for i, op := range operators {
		if op == (common.Address{}) {
			return nil, fmt.Errorf("%w: operator at index %d is zero", ErrInvalidQuorumConfig, i)
		}
		if _, ok := ops[op]; ok {
			return nil, fmt.Errorf("%w: duplicate operator %s", ErrInvalidQuorumConfig, op.Hex())
		}
		ops[op] = struct{}{}
	}
	if threshold > len(ops) {
		return nil, fmt.Errorf("%w: threshold %d > operators %d", ErrInvalidQuorumConfig, threshold, len(ops))
	}

	return &QuorumVerifier{
		operators: ops,
		threshold: threshold,
	}, nil
}

func (v *QuorumVerifier) VerifyCheckpointSignatures(cp Checkpoint, sigs [][]byte) ([]common.Address, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrInvalidQuorumConfig)
	}
	return v.VerifyDigestSignatures(Digest(cp), sigs)
}

func (v *QuorumVerifier) VerifyDigestSignatures(digest common.Hash, sigs [][]byte) ([]common.Address, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrInvalidQuorumConfig)
	}
	if len(sigs) < v.threshold {
		return nil, ErrInsufficientSignatures
	}

	signers := make([]common.Address, 0, len(sigs))
	var prev common.Address
	for i, sig := range sigs {
		ns, err := normalizeSignatureV(sig)
		if err != nil {
			return nil, err
		}
		signer, err := RecoverSigner(digest, ns)
		if err != nil {
			return nil, err
		}
		if i > 0 && bytes.Compare(signer[:], prev[:]) <= 0 {
			return nil, ErrUnsortedSignatures
		}
		if _, ok := v.operators[signer]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownSigner, signer.Hex())
		}
		prev = signer
		signers = append(signers, signer)
	}

	if len(signers) < v.threshold {
		return nil, ErrInsufficientSignatures
	}
	return signers, nil
}

func ParseOperatorAddressesCSV(csv string) ([]common.Address, error) {
	parts := splitAndTrim(csv)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: empty operator address list", ErrInvalidQuorumConfig)
	}
	out := make([]common.Address, 0, len(parts))
	seen := make(map[common.Address]struct{}, len(parts))
	for i, p := range parts {
		if !common.IsHexAddress(p) {
			return nil, fmt.Errorf("%w: invalid operator address at index %d", ErrInvalidQuorumConfig, i)
		}
		a := common.HexToAddress(p)
		if _, ok := seen[a]; ok {
			return nil, fmt.Errorf("%w: duplicate operator %s", ErrInvalidQuorumConfig, a.Hex())
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b common.Address) int { return bytes.Compare(a[:], b[:]) })
	return out, nil
}

func splitAndTrim(csv string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(csv); i++ {
		ch := csv[i]
		if ch == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
