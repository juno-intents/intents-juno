package deposit

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type MemoryStore struct {
	mu sync.Mutex

	jobs  map[[32]byte]Job
	order [][32]byte
	claim map[[32]byte]claimLease

	batches        map[[32]byte]Batch
	batchOrder     [][32]byte
	batchByDeposit map[[32]byte][32]byte

	attempts         map[[32]byte]SubmittedBatchAttempt
	attemptOrder     [][32]byte
	attemptClaim     map[[32]byte]claimLease
	attemptByDeposit map[[32]byte][32]byte
	sourceEvents     map[sourceEventKey][32]byte
}

type claimLease struct {
	owner     string
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs:             make(map[[32]byte]Job),
		claim:            make(map[[32]byte]claimLease),
		batches:          make(map[[32]byte]Batch),
		batchByDeposit:   make(map[[32]byte][32]byte),
		attempts:         make(map[[32]byte]SubmittedBatchAttempt),
		attemptClaim:     make(map[[32]byte]claimLease),
		attemptByDeposit: make(map[[32]byte][32]byte),
		sourceEvents:     make(map[sourceEventKey][32]byte),
	}
}

type sourceEventKey struct {
	chainID  uint64
	txHash   [32]byte
	logIndex uint64
}

func (s *MemoryStore) UpsertSeen(_ context.Context, d Deposit) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.recordSourceEvent(d); err != nil {
		return Job{}, false, err
	}

	j, ok := s.jobs[d.DepositID]
	if !ok {
		j = Job{
			Deposit: d,
			State:   StateSeen,
		}
		s.jobs[d.DepositID] = j
		s.order = append(s.order, d.DepositID)
		return j, true, nil
	}

	if !depositIdentityEqual(j.Deposit, d) {
		return Job{}, false, ErrDepositMismatch
	}
	if j.State < StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(j.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		j.Deposit.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	}
	if d.JunoHeight > 0 {
		j.Deposit.JunoHeight = d.JunoHeight
	}
	s.jobs[d.DepositID] = j
	return cloneJob(j), false, nil
}

func (s *MemoryStore) UpsertConfirmed(_ context.Context, d Deposit) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.recordSourceEvent(d); err != nil {
		return Job{}, false, err
	}

	j, ok := s.jobs[d.DepositID]
	if !ok {
		j = Job{
			Deposit: d,
			State:   StateConfirmed,
		}
		s.jobs[d.DepositID] = j
		s.order = append(s.order, d.DepositID)
		return j, true, nil
	}

	if !depositIdentityEqual(j.Deposit, d) {
		return Job{}, false, ErrDepositMismatch
	}
	if j.State < StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(j.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		j.Deposit.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	}
	if d.JunoHeight > 0 {
		j.Deposit.JunoHeight = d.JunoHeight
	}

	if j.State < StateConfirmed {
		j.State = StateConfirmed
		j.RejectionReason = ""
		s.jobs[d.DepositID] = j
		delete(s.claim, d.DepositID)
	}
	return cloneJob(j), false, nil
}

func (s *MemoryStore) PromoteSeenToConfirmed(_ context.Context, tipHeight int64, minConfirmations int64, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tipHeight <= 0 || minConfirmations <= 0 || limit <= 0 {
		return nil, nil
	}

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		if len(out) >= limit {
			break
		}
		j := s.jobs[id]
		if j.State != StateSeen || j.Deposit.JunoHeight <= 0 {
			continue
		}
		if tipHeight-j.Deposit.JunoHeight+1 < minConfirmations {
			continue
		}
		j.State = StateConfirmed
		j.RejectionReason = ""
		s.jobs[id] = j
		out = append(out, cloneJob(j))
	}
	return out, nil
}

func (s *MemoryStore) Get(_ context.Context, depositID [32]byte) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return Job{}, ErrNotFound
	}

	// Defensive copy of slices.
	j.Deposit = cloneDeposit(j.Deposit)
	if j.ProofSeal != nil {
		j.ProofSeal = append([]byte(nil), j.ProofSeal...)
	}
	return j, nil
}

func (s *MemoryStore) GetBatch(_ context.Context, batchID [32]byte) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	batch, ok := s.batches[batchID]
	if !ok {
		return Batch{}, ErrNotFound
	}
	return cloneBatch(batch), nil
}

func (s *MemoryStore) ListByState(_ context.Context, state State, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		return nil, nil
	}

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		j := s.jobs[id]
		if j.State != state {
			continue
		}
		j.Deposit = cloneDeposit(j.Deposit)
		if j.ProofSeal != nil {
			j.ProofSeal = append([]byte(nil), j.ProofSeal...)
		}
		out = append(out, j)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) ClaimConfirmed(_ context.Context, owner string, ttl time.Duration, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		j := s.jobs[id]
		if j.State != StateConfirmed && j.State != StateProofRequested {
			continue
		}
		lease, claimed := s.claim[id]
		if claimed && lease.owner != owner && lease.expiresAt.After(now) {
			continue
		}
		s.claim[id] = claimLease{
			owner:     owner,
			expiresAt: expiresAt,
		}
		j.Deposit = cloneDeposit(j.Deposit)
		if j.ProofSeal != nil {
			j.ProofSeal = append([]byte(nil), j.ProofSeal...)
		}
		out = append(out, j)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) ClaimSubmittedAttempts(_ context.Context, owner string, ttl time.Duration, limit int) ([]SubmittedBatchAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	out := make([]SubmittedBatchAttempt, 0, limit)
	for _, batchID := range s.attemptOrder {
		attempt, ok := s.attempts[batchID]
		if !ok {
			continue
		}
		lease, claimed := s.attemptClaim[batchID]
		if claimed && lease.owner != owner && lease.expiresAt.After(now) {
			continue
		}
		s.attemptClaim[batchID] = claimLease{
			owner:     owner,
			expiresAt: expiresAt,
		}
		out = append(out, cloneSubmittedBatchAttempt(attempt))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) PrepareNextBatch(_ context.Context, owner string, ttl time.Duration, nextBatchID [32]byte, maxItems int, maxAge time.Duration, limit int, now time.Time) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || ttl <= 0 || maxItems <= 0 || maxAge <= 0 || limit <= 0 {
		return Batch{}, false, ErrInvalidTransition
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if batchID, ok := s.findActionableBatchID(owner, now); ok {
		batch := s.batches[batchID]
		batch.LeaseOwner = owner
		batch.LeaseExpiresAt = now.Add(ttl)
		s.batches[batchID] = batch
		return cloneBatch(batch), true, nil
	}

	batchID, ok := s.findAssemblingBatchID()
	if ok {
		batch := s.batches[batchID]
		batch.LeaseOwner = owner
		batch.LeaseExpiresAt = now.Add(ttl)
		if len(batch.DepositIDs) >= maxItems || now.Sub(batch.StartedAt) >= maxAge {
			batch.State = BatchStateClosed
			if batch.ClosedAt.IsZero() {
				batch.ClosedAt = now
			}
			s.batches[batchID] = batch
			return cloneBatch(batch), true, nil
		}

		if nextID, found := s.nextConfirmedDepositForBatch(batchID); found {
			batch.DepositIDs = append(batch.DepositIDs, nextID)
			s.batchByDeposit[nextID] = batchID
			if len(batch.DepositIDs) >= maxItems {
				batch.State = BatchStateClosed
				batch.ClosedAt = now
				s.batches[batchID] = batch
				return cloneBatch(batch), true, nil
			}
			s.batches[batchID] = batch
		} else {
			s.batches[batchID] = batch
		}
		return cloneBatch(batch), false, nil
	}

	if nextBatchID == ([32]byte{}) {
		return Batch{}, false, ErrInvalidTransition
	}
	if _, exists := s.batches[nextBatchID]; exists {
		return Batch{}, false, ErrDepositMismatch
	}

	depositID, found := s.nextConfirmedDepositForBatch([32]byte{})
	if !found {
		return Batch{}, false, nil
	}

	batch := Batch{
		BatchID:     nextBatchID,
		State:       BatchStateAssembling,
		DepositIDs:  [][32]byte{depositID},
		Owner:       owner,
		LeaseOwner:  owner,
		LeaseExpiresAt: now.Add(ttl),
		StartedAt:   now,
		FailureReason: "",
	}
	s.batches[nextBatchID] = batch
	s.batchOrder = append(s.batchOrder, nextBatchID)
	s.batchByDeposit[depositID] = nextBatchID

	if maxItems == 1 {
		batch.State = BatchStateClosed
		batch.ClosedAt = now
		s.batches[nextBatchID] = batch
		return cloneBatch(batch), true, nil
	}
	return cloneBatch(batch), false, nil
}

func (s *MemoryStore) SplitBatch(_ context.Context, owner string, batchID [32]byte, nextBatchID [32]byte, movedDepositIDs [][32]byte) (Batch, Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || nextBatchID == ([32]byte{}) {
		return Batch{}, Batch{}, ErrInvalidTransition
	}
	if _, exists := s.batches[nextBatchID]; exists {
		return Batch{}, Batch{}, ErrDepositMismatch
	}

	left, ok := s.batches[batchID]
	if !ok {
		return Batch{}, Batch{}, ErrNotFound
	}
	if left.State != BatchStateClosed {
		return Batch{}, Batch{}, ErrInvalidTransition
	}

	moveSet := make(map[[32]byte]struct{}, len(movedDepositIDs))
	for _, id := range uniqueDepositIDs(movedDepositIDs) {
		moveSet[id] = struct{}{}
	}
	if len(moveSet) == 0 || len(moveSet) >= len(left.DepositIDs) {
		return Batch{}, Batch{}, ErrInvalidTransition
	}

	stay := make([][32]byte, 0, len(left.DepositIDs))
	move := make([][32]byte, 0, len(moveSet))
	for _, id := range left.DepositIDs {
		if _, ok := moveSet[id]; ok {
			move = append(move, id)
			continue
		}
		stay = append(stay, id)
	}
	if len(move) != len(moveSet) || len(stay) == 0 {
		return Batch{}, Batch{}, ErrDepositMismatch
	}

	left.DepositIDs = stay
	left.LeaseOwner = owner
	s.batches[batchID] = left

	right := Batch{
		BatchID:            nextBatchID,
		State:              BatchStateClosed,
		DepositIDs:         move,
		Owner:              left.Owner,
		LeaseOwner:         owner,
		StartedAt:          left.StartedAt,
		ClosedAt:           left.ClosedAt,
		FailureReason:      left.FailureReason,
		Checkpoint:         left.Checkpoint,
		ProofRequested:     left.ProofRequested,
		OperatorSignatures: clone2DBytes(left.OperatorSignatures),
		ProofSeal:          append([]byte(nil), left.ProofSeal...),
		TxHash:             left.TxHash,
	}
	s.batches[nextBatchID] = right
	s.batchOrder = append(s.batchOrder, nextBatchID)
	for _, id := range move {
		s.batchByDeposit[id] = nextBatchID
	}

	return cloneBatch(left), cloneBatch(right), nil
}

func (s *MemoryStore) MarkProofRequested(_ context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateConfirmed {
		return ErrInvalidTransition
	}

	// Do not allow downgrades.
	if j.State < StateProofRequested {
		j.State = StateProofRequested
	}
	j.Checkpoint = cp
	s.jobs[depositID] = j
	return nil
}

func (s *MemoryStore) MarkBatchProofRequested(_ context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" {
		return Batch{}, ErrInvalidTransition
	}
	batch, ok := s.batches[batchID]
	if !ok {
		return Batch{}, ErrNotFound
	}
	if batch.State != BatchStateClosed && batch.State != BatchStateProofRequested && batch.State != BatchStateProofReady && batch.State != BatchStateSubmitted {
		return Batch{}, ErrInvalidTransition
	}
	if batch.State < BatchStateProofRequested {
		batch.State = BatchStateProofRequested
	}
	batch.Checkpoint = cp
	batch.ProofRequested = true
	batch.LeaseOwner = owner
	s.batches[batchID] = batch

	for _, depositID := range batch.DepositIDs {
		j, ok := s.jobs[depositID]
		if !ok {
			return Batch{}, ErrNotFound
		}
		if j.State == StateRejected {
			return Batch{}, ErrInvalidTransition
		}
		if j.State < StateConfirmed {
			return Batch{}, ErrInvalidTransition
		}
		if j.State < StateProofRequested {
			j.State = StateProofRequested
		}
		j.Checkpoint = cp
		s.jobs[depositID] = j
	}
	return cloneBatch(batch), nil
}

func (s *MemoryStore) SetProofReady(_ context.Context, depositID [32]byte, seal []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateProofRequested {
		return ErrInvalidTransition
	}

	if j.State < StateProofReady {
		j.State = StateProofReady
		delete(s.claim, depositID)
	}
	j.ProofSeal = append([]byte(nil), seal...)
	s.jobs[depositID] = j
	return nil
}

func (s *MemoryStore) MarkBatchProofReady(_ context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" {
		return Batch{}, ErrInvalidTransition
	}
	batch, ok := s.batches[batchID]
	if !ok {
		return Batch{}, ErrNotFound
	}
	if batch.State != BatchStateProofRequested && batch.State != BatchStateProofReady && batch.State != BatchStateSubmitted {
		return Batch{}, ErrInvalidTransition
	}
	if batch.State < BatchStateProofReady {
		batch.State = BatchStateProofReady
	}
	batch.Checkpoint = cp
	batch.ProofRequested = true
	batch.OperatorSignatures = clone2DBytes(operatorSignatures)
	batch.ProofSeal = append([]byte(nil), seal...)
	batch.LeaseOwner = owner
	s.batches[batchID] = batch

	for _, depositID := range batch.DepositIDs {
		j, ok := s.jobs[depositID]
		if !ok {
			return Batch{}, ErrNotFound
		}
		if j.State == StateRejected {
			return Batch{}, ErrInvalidTransition
		}
		if j.State < StateProofRequested {
			return Batch{}, ErrInvalidTransition
		}
		if j.State < StateProofReady {
			j.State = StateProofReady
			delete(s.claim, depositID)
		}
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		s.jobs[depositID] = j
	}
	return cloneBatch(batch), nil
}

func (s *MemoryStore) MarkFinalized(_ context.Context, depositID [32]byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateProofReady {
		return ErrInvalidTransition
	}

	if j.State == StateFinalized {
		if j.TxHash != txHash {
			return ErrDepositMismatch
		}
		return nil
	}

	j.State = StateFinalized
	j.TxHash = txHash
	j.RejectionReason = ""
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	delete(s.batchByDeposit, depositID)
	return nil
}

func (s *MemoryStore) RepairFinalized(_ context.Context, depositID [32]byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}
	if j.State < StateConfirmed {
		return ErrInvalidTransition
	}
	if j.State == StateFinalized {
		if j.TxHash != txHash {
			return ErrDepositMismatch
		}
		return nil
	}

	j.State = StateFinalized
	j.TxHash = txHash
	j.RejectionReason = ""
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	delete(s.batchByDeposit, depositID)
	return nil
}

func (s *MemoryStore) MarkRejected(_ context.Context, depositID [32]byte, reason string, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}
	if j.State == StateFinalized {
		return ErrInvalidTransition
	}
	if j.State == StateRejected {
		if j.RejectionReason != reason {
			return ErrDepositMismatch
		}
		if txHash != ([32]byte{}) && j.TxHash != ([32]byte{}) && j.TxHash != txHash {
			return ErrDepositMismatch
		}
		return nil
	}
	if j.State < StateSeen {
		return ErrInvalidTransition
	}

	j.State = StateRejected
	j.RejectionReason = reason
	if txHash != ([32]byte{}) {
		j.TxHash = txHash
	}
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	delete(s.batchByDeposit, depositID)
	delete(s.attemptByDeposit, depositID)
	return nil
}

func (s *MemoryStore) FailBatch(_ context.Context, owner string, batchID [32]byte, reason string, rejectedIDs [][32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || reason == "" {
		return ErrInvalidTransition
	}
	batch, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}
	rejected := make(map[[32]byte]struct{}, len(rejectedIDs))
	for _, id := range uniqueDepositIDs(rejectedIDs) {
		rejected[id] = struct{}{}
	}

	batch.State = BatchStateFailed
	batch.LeaseOwner = owner
	batch.FailureReason = reason
	s.batches[batchID] = batch

	for _, depositID := range batch.DepositIDs {
		j, ok := s.jobs[depositID]
		if !ok {
			return ErrNotFound
		}
		if _, shouldReject := rejected[depositID]; shouldReject {
			if j.State != StateFinalized {
				j.State = StateRejected
				j.RejectionReason = reason
				j.TxHash = [32]byte{}
			}
			s.jobs[depositID] = j
			delete(s.claim, depositID)
			delete(s.batchByDeposit, depositID)
			delete(s.attemptByDeposit, depositID)
			continue
		}
		if j.State != StateFinalized && j.State != StateRejected {
			j.State = StateConfirmed
			j.Checkpoint = checkpoint.Checkpoint{}
			j.ProofSeal = nil
			j.TxHash = [32]byte{}
			j.RejectionReason = ""
			s.jobs[depositID] = j
		}
		delete(s.claim, depositID)
		delete(s.batchByDeposit, depositID)
	}
	return nil
}

func (s *MemoryStore) MarkBatchSubmitted(_ context.Context, owner string, batchID [32]byte, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (SubmittedBatchAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return SubmittedBatchAttempt{}, nil
	}
	if owner == "" {
		return SubmittedBatchAttempt{}, ErrInvalidTransition
	}

	ids := uniqueDepositIDs(depositIDs)

	for _, id := range ids {
		j, ok := s.jobs[id]
		if !ok {
			return SubmittedBatchAttempt{}, ErrNotFound
		}
		if j.State == StateRejected {
			return SubmittedBatchAttempt{}, ErrInvalidTransition
		}
		if j.State < StateConfirmed {
			return SubmittedBatchAttempt{}, ErrInvalidTransition
		}
	}

	if existing, ok := s.attempts[batchID]; ok {
		if !submittedBatchAttemptEqual(existing, owner, ids, cp, operatorSignatures, seal) {
			return SubmittedBatchAttempt{}, ErrDepositMismatch
		}
		if batch, ok := s.batches[batchID]; ok {
			batch.State = BatchStateSubmitted
			batch.Checkpoint = cp
			batch.ProofRequested = true
			batch.OperatorSignatures = clone2DBytes(operatorSignatures)
			batch.ProofSeal = append([]byte(nil), seal...)
			batch.LeaseOwner = owner
			s.batches[batchID] = batch
		}
		for _, id := range ids {
			s.attemptByDeposit[id] = batchID
		}
		return cloneSubmittedBatchAttempt(existing), nil
	}

	attempt := SubmittedBatchAttempt{
		BatchID:            batchID,
		DepositIDs:         cloneDepositIDs(ids),
		Owner:              owner,
		Epoch:              1,
		Checkpoint:         cp,
		OperatorSignatures: clone2DBytes(operatorSignatures),
		ProofSeal:          append([]byte(nil), seal...),
	}
	s.attempts[batchID] = attempt
	s.attemptOrder = append(s.attemptOrder, batchID)
	if batch, ok := s.batches[batchID]; ok {
		batch.State = BatchStateSubmitted
		batch.Checkpoint = cp
		batch.ProofRequested = true
		batch.OperatorSignatures = clone2DBytes(operatorSignatures)
		batch.ProofSeal = append([]byte(nil), seal...)
		batch.LeaseOwner = owner
		s.batches[batchID] = batch
	} else {
		s.batches[batchID] = Batch{
			BatchID:            batchID,
			State:              BatchStateSubmitted,
			DepositIDs:         cloneDepositIDs(ids),
			Owner:              owner,
			LeaseOwner:         owner,
			StartedAt:          time.Now().UTC(),
			ClosedAt:           time.Now().UTC(),
			Checkpoint:         cp,
			ProofRequested:     true,
			OperatorSignatures: clone2DBytes(operatorSignatures),
			ProofSeal:          append([]byte(nil), seal...),
		}
		s.batchOrder = append(s.batchOrder, batchID)
	}

	for _, id := range ids {
		j := s.jobs[id]
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		if j.State != StateFinalized && j.State != StateRejected {
			j.State = StateSubmitted
		}
		j.RejectionReason = ""
		s.jobs[id] = j
		delete(s.claim, id)
		s.batchByDeposit[id] = batchID
		s.attemptByDeposit[id] = batchID
	}
	return cloneSubmittedBatchAttempt(attempt), nil
}

func (s *MemoryStore) SetBatchSubmissionTxHash(_ context.Context, batchID [32]byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.attempts[batchID]
	if !ok {
		return ErrNotFound
	}
	if attempt.TxHash != ([32]byte{}) && attempt.TxHash != txHash {
		return ErrDepositMismatch
	}
	attempt.TxHash = txHash
	s.attempts[batchID] = attempt
	if batch, ok := s.batches[batchID]; ok {
		batch.State = BatchStateSubmitted
		batch.TxHash = txHash
		s.batches[batchID] = batch
	}
	return nil
}

func (s *MemoryStore) RequeueSubmittedBatch(_ context.Context, batchID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.attempts[batchID]
	if !ok {
		return ErrNotFound
	}
	if attempt.TxHash != ([32]byte{}) {
		return ErrInvalidTransition
	}

	for _, id := range attempt.DepositIDs {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateSubmitted {
			j.State = StateConfirmed
			j.ProofSeal = nil
			j.TxHash = [32]byte{}
			j.RejectionReason = ""
			s.jobs[id] = j
		}
		delete(s.claim, id)
		s.batchByDeposit[id] = batchID
		delete(s.attemptByDeposit, id)
	}

	if batch, ok := s.batches[batchID]; ok {
		batch.State = BatchStateClosed
		batch.ProofSeal = nil
		batch.TxHash = [32]byte{}
		batch.OperatorSignatures = nil
		batch.Checkpoint = checkpoint.Checkpoint{}
		batch.LeaseOwner = ""
		s.batches[batchID] = batch
	}

	delete(s.attempts, batchID)
	delete(s.attemptClaim, batchID)
	nextOrder := s.attemptOrder[:0]
	for _, existing := range s.attemptOrder {
		if existing == batchID {
			continue
		}
		nextOrder = append(nextOrder, existing)
	}
	s.attemptOrder = nextOrder
	return nil
}

func (s *MemoryStore) FinalizeBatch(_ context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return nil
	}

	ids := uniqueDepositIDs(depositIDs)
	batchIDs := make(map[[32]byte]struct{}, len(ids))

	// Validate first so the operation is all-or-nothing.
	for _, id := range ids {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateFinalized {
			if j.TxHash != txHash {
				return ErrDepositMismatch
			}
			continue
		}
		if j.State < StateConfirmed {
			return ErrInvalidTransition
		}
		if batchID, ok := s.attemptByDeposit[id]; ok {
			batchIDs[batchID] = struct{}{}
		}
	}

	for _, id := range ids {
		j := s.jobs[id]
		if j.State == StateFinalized {
			delete(s.claim, id)
			delete(s.batchByDeposit, id)
			delete(s.attemptByDeposit, id)
			continue
		}
		j.State = StateFinalized
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		j.TxHash = txHash
		j.RejectionReason = ""
		s.jobs[id] = j
		delete(s.claim, id)
		delete(s.batchByDeposit, id)
		delete(s.attemptByDeposit, id)
	}
	for batchID := range batchIDs {
		delete(s.attempts, batchID)
		delete(s.attemptClaim, batchID)
		if batch, ok := s.batches[batchID]; ok {
			batch.State = BatchStateFinalized
			batch.Checkpoint = cp
			batch.ProofSeal = append([]byte(nil), seal...)
			batch.TxHash = txHash
			s.batches[batchID] = batch
		}
	}
	return nil
}

func (s *MemoryStore) ApplyBatchOutcome(_ context.Context, batchID [32]byte, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.attempts[batchID]
	if !ok {
		return ErrNotFound
	}

	expected := make(map[[32]byte]struct{}, len(attempt.DepositIDs))
	for _, id := range attempt.DepositIDs {
		expected[id] = struct{}{}
	}
	finalizedSet := make(map[[32]byte]struct{}, len(finalizedIDs))
	rejectedSet := make(map[[32]byte]struct{}, len(rejectedIDs))
	for _, id := range uniqueDepositIDs(finalizedIDs) {
		if _, ok := expected[id]; !ok {
			return ErrDepositMismatch
		}
		finalizedSet[id] = struct{}{}
	}
	for _, id := range uniqueDepositIDs(rejectedIDs) {
		if _, ok := expected[id]; !ok {
			return ErrDepositMismatch
		}
		if _, ok := finalizedSet[id]; ok {
			return ErrDepositMismatch
		}
		rejectedSet[id] = struct{}{}
	}

	allResolved := true
	for _, id := range attempt.DepositIDs {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateFinalized || j.State == StateRejected {
			delete(s.claim, id)
			delete(s.batchByDeposit, id)
			delete(s.attemptByDeposit, id)
			s.jobs[id] = j
			continue
		}
		switch {
		case hasID(finalizedSet, id):
			j.State = StateFinalized
			j.RejectionReason = ""
			j.TxHash = txHash
			delete(s.batchByDeposit, id)
			delete(s.attemptByDeposit, id)
		case hasID(rejectedSet, id):
			j.State = StateRejected
			j.RejectionReason = rejectionReason
			j.TxHash = txHash
			delete(s.batchByDeposit, id)
			delete(s.attemptByDeposit, id)
		default:
			allResolved = false
			if j.State != StateFinalized && j.State != StateRejected {
				j.State = StateSubmitted
				j.TxHash = txHash
			}
			s.batchByDeposit[id] = batchID
			s.attemptByDeposit[id] = batchID
		}
		delete(s.claim, id)
		s.jobs[id] = j
	}
	if batch, ok := s.batches[batchID]; ok {
		batch.Checkpoint = attempt.Checkpoint
		batch.OperatorSignatures = clone2DBytes(attempt.OperatorSignatures)
		batch.ProofSeal = append([]byte(nil), attempt.ProofSeal...)
		batch.TxHash = txHash
		if allResolved {
			batch.State = BatchStateFinalized
		} else {
			batch.State = BatchStateSubmitted
		}
		s.batches[batchID] = batch
	}
	if allResolved {
		delete(s.attempts, batchID)
		delete(s.attemptClaim, batchID)
	}
	return nil
}

func (s *MemoryStore) findActionableBatchID(owner string, now time.Time) ([32]byte, bool) {
	for _, batchID := range s.batchOrder {
		batch, ok := s.batches[batchID]
		if !ok {
			continue
		}
		if batch.LeaseOwner != "" && batch.LeaseOwner != owner && batch.LeaseExpiresAt.After(now) {
			continue
		}
		switch batch.State {
		case BatchStateClosed, BatchStateProofRequested, BatchStateProofReady:
			return batchID, true
		}
	}
	return [32]byte{}, false
}

func (s *MemoryStore) findAssemblingBatchID() ([32]byte, bool) {
	for _, batchID := range s.batchOrder {
		batch, ok := s.batches[batchID]
		if !ok {
			continue
		}
		if batch.State == BatchStateAssembling {
			return batchID, true
		}
	}
	return [32]byte{}, false
}

func (s *MemoryStore) nextConfirmedDepositForBatch(batchID [32]byte) ([32]byte, bool) {
	for _, depositID := range s.order {
		job, ok := s.jobs[depositID]
		if !ok || job.State != StateConfirmed {
			continue
		}
		if existing, claimed := s.batchByDeposit[depositID]; claimed && existing != batchID {
			continue
		}
		if _, attempted := s.attemptByDeposit[depositID]; attempted {
			continue
		}
		if batchID != ([32]byte{}) {
			if existing, claimed := s.batchByDeposit[depositID]; claimed && existing == batchID {
				continue
			}
		}
		return depositID, true
	}
	return [32]byte{}, false
}

func uniqueDepositIDs(ids [][32]byte) [][32]byte {
	out := make([][32]byte, 0, len(ids))
	seen := make(map[[32]byte]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func cloneDeposit(d Deposit) Deposit {
	d.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	if d.SourceEvent != nil {
		src := *d.SourceEvent
		d.SourceEvent = &src
	}
	return d
}

func cloneJob(j Job) Job {
	j.Deposit = cloneDeposit(j.Deposit)
	j.ProofSeal = append([]byte(nil), j.ProofSeal...)
	return j
}

func cloneSubmittedBatchAttempt(a SubmittedBatchAttempt) SubmittedBatchAttempt {
	a.DepositIDs = cloneDepositIDs(a.DepositIDs)
	a.OperatorSignatures = clone2DBytes(a.OperatorSignatures)
	a.ProofSeal = append([]byte(nil), a.ProofSeal...)
	return a
}

func cloneBatch(b Batch) Batch {
	b.DepositIDs = cloneDepositIDs(b.DepositIDs)
	b.OperatorSignatures = clone2DBytes(b.OperatorSignatures)
	b.ProofSeal = append([]byte(nil), b.ProofSeal...)
	return b
}

func cloneDepositIDs(ids [][32]byte) [][32]byte {
	if len(ids) == 0 {
		return nil
	}
	out := make([][32]byte, len(ids))
	copy(out, ids)
	return out
}

func clone2DBytes(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(in))
	for _, item := range in {
		out = append(out, append([]byte(nil), item...))
	}
	return out
}

func submittedBatchAttemptEqual(existing SubmittedBatchAttempt, owner string, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) bool {
	if existing.Owner != owner || existing.Checkpoint != cp {
		return false
	}
	if !bytes.Equal(existing.ProofSeal, seal) {
		return false
	}
	if len(existing.DepositIDs) != len(depositIDs) || len(existing.OperatorSignatures) != len(operatorSignatures) {
		return false
	}
	for i := range existing.DepositIDs {
		if existing.DepositIDs[i] != depositIDs[i] {
			return false
		}
	}
	for i := range existing.OperatorSignatures {
		if !bytes.Equal(existing.OperatorSignatures[i], operatorSignatures[i]) {
			return false
		}
	}
	return true
}

func depositIdentityEqual(a, b Deposit) bool {
	return a.DepositID == b.DepositID &&
		a.Commitment == b.Commitment &&
		a.LeafIndex == b.LeafIndex &&
		a.Amount == b.Amount &&
		a.BaseRecipient == b.BaseRecipient
}

func depositEqual(a, b Deposit) bool {
	return depositIdentityEqual(a, b) && a.JunoHeight == b.JunoHeight
}

func (s *MemoryStore) recordSourceEvent(d Deposit) error {
	if d.SourceEvent == nil {
		return nil
	}
	if d.SourceEvent.ChainID == 0 {
		return ErrDepositMismatch
	}
	key := sourceEventKey{
		chainID:  d.SourceEvent.ChainID,
		txHash:   d.SourceEvent.TxHash,
		logIndex: d.SourceEvent.LogIndex,
	}
	if existing, ok := s.sourceEvents[key]; ok && existing != d.DepositID {
		return ErrDepositMismatch
	}
	s.sourceEvents[key] = d.DepositID
	return nil
}

func hasID(ids map[[32]byte]struct{}, id [32]byte) bool {
	_, ok := ids[id]
	return ok
}
