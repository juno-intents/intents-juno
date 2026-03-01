package e2eorch

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// E2EConfig holds all external coordinates needed by the e2e orchestrator.
// Every field is populated from environment variables or test flags; nothing
// is discovered at runtime.
type E2EConfig struct {
	// -- HTTP endpoints --
	BridgeAPIURL string
	BaseRPCURL   string
	BaseChainID  uint64
	JunoRPCURL   string
	JunoRPCUser  string
	JunoRPCPass  string

	// -- Contract addresses --
	BridgeAddress         common.Address
	WJunoAddress          common.Address
	FeeDistributorAddress common.Address
	RecipientAddress      common.Address // Base address that receives minted wJUNO

	// -- Juno wallet --
	JunoFunderSourceAddress string // t-addr or UA that funds the deposit
	OWalletUA               string // Orchard wallet UA for the bridge
	JunoWalletID            string // wallet name used by juno-cli

	// -- Test amounts --
	DepositAmountZat uint64
	WithdrawAmount   uint64

	// -- Withdrawal params --
	WithdrawRecipientRawHex string // 43-byte raw UA hex for withdrawal recipient

	// -- Observability / tooling --
	JunoScanURL         string
	JunoScanBearerToken string
	WitnessExtractBin   string

	// -- Timeouts --
	RunTimeout      time.Duration
	DepositTimeout  time.Duration
	WithdrawTimeout time.Duration
	PollInterval    time.Duration

	// -- IPFS --
	IPFSAPIUrl string

	// -- Expected fee parameters --
	ExpectedFeeBps uint64
	ExpectedTipBps uint64
}

// DepositResult captures the outcome and timing of a full deposit flow.
type DepositResult struct {
	Success   bool   `json:"success"`
	DepositID string `json:"depositId,omitempty"`
	Amount    string `json:"amount,omitempty"`

	// Timing breakdown.
	MemoFetchedAt *time.Time `json:"memoFetchedAt,omitempty"`
	JunoSentAt    *time.Time `json:"junoSentAt,omitempty"`
	SubmittedAt   *time.Time `json:"submittedAt,omitempty"`
	FinalizedAt   *time.Time `json:"finalizedAt,omitempty"`
	TotalDuration string     `json:"totalDuration,omitempty"`

	// On-chain confirmation.
	BaseTxHash  string `json:"baseTxHash,omitempty"`
	DepositUsed bool   `json:"depositUsed"`
	WJunoMinted string `json:"wjunoMinted,omitempty"` // balance delta

	// Final API state.
	FinalState string `json:"finalState,omitempty"`

	Error string `json:"error,omitempty"`
}

// BridgeConfigResponse mirrors the JSON returned by GET /v1/config.
type BridgeConfigResponse struct {
	Version             string `json:"version"`
	BaseChainID         uint32 `json:"baseChainId"`
	BridgeAddress       string `json:"bridgeAddress"`
	OWalletUA           string `json:"oWalletUA"`
	RefundWindowSeconds uint64 `json:"refundWindowSeconds"`
	MinDepositAmount    string `json:"minDepositAmount"`
	MinWithdrawAmount   string `json:"minWithdrawAmount"`
}

// DepositMemoResponse mirrors the JSON returned by GET /v1/deposit-memo.
type DepositMemoResponse struct {
	Version       string `json:"version"`
	BaseChainID   uint32 `json:"baseChainId"`
	BridgeAddress string `json:"bridgeAddress"`
	OWalletUA     string `json:"oWalletUA"`
	BaseRecipient string `json:"baseRecipient"`
	Nonce         string `json:"nonce"`
	MemoHex       string `json:"memoHex"`
	MemoBase64    string `json:"memoBase64"`
}

// DepositSubmitRequest is the POST body for /v1/deposits/submit.
type DepositSubmitRequest struct {
	BaseRecipient    string `json:"baseRecipient"`
	Amount           string `json:"amount"`
	Nonce            string `json:"nonce"`
	ProofWitnessItem string `json:"proofWitnessItem"`
}

// DepositSubmitResponse mirrors the JSON returned by POST /v1/deposits/submit.
type DepositSubmitResponse struct {
	Version   string `json:"version"`
	Queued    bool   `json:"queued"`
	DepositID string `json:"depositId"`
	Amount    string `json:"amount"`
}

// DepositStatusResponse mirrors the JSON returned by GET /v1/status/deposit/{id}.
type DepositStatusResponse struct {
	Version       string `json:"version"`
	Found         bool   `json:"found"`
	DepositID     string `json:"depositId"`
	State         string `json:"state"`
	Amount        string `json:"amount"`
	BaseRecipient string `json:"baseRecipient"`
	TxHash        string `json:"txHash"`
}

// WithdrawalRequestRequest is the POST body for /v1/withdrawals/request.
type WithdrawalRequestRequest struct {
	Amount                 string `json:"amount"`
	RecipientRawAddressHex string `json:"recipientRawAddressHex"`
}

// WithdrawalRequestResponse mirrors the JSON returned by POST /v1/withdrawals/request.
type WithdrawalRequestResponse struct {
	Version       string `json:"version"`
	Queued        bool   `json:"queued"`
	WithdrawalID  string `json:"withdrawalId"`
	Requester     string `json:"requester"`
	Amount        string `json:"amount"`
	RecipientUA   string `json:"recipientUA"`
	Expiry        string `json:"expiry"`
	FeeBps        uint64 `json:"feeBps"`
	ApproveTxHash string `json:"approveTxHash"`
	RequestTxHash string `json:"requestTxHash"`
}

// WithdrawalStatusResponse mirrors the JSON returned by GET /v1/status/withdrawal/{id}.
type WithdrawalStatusResponse struct {
	Version      string `json:"version"`
	Found        bool   `json:"found"`
	WithdrawalID string `json:"withdrawalId"`
	State        string `json:"state"`
	Amount       string `json:"amount"`
	FeeBps       uint64 `json:"feeBps"`
	Requester    string `json:"requester"`
	Expiry       string `json:"expiry"`
	BatchID      string `json:"batchId"`
	JunoTxID     string `json:"junoTxId"`
	BaseTxHash   string `json:"baseTxHash"`
}
