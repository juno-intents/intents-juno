package httpapi

// SendRequest is the request body for POST /v1/send.
type SendRequest struct {
	To             string `json:"to"`
	Data           string `json:"data,omitempty"`
	ValueWei       string `json:"value_wei,omitempty"`
	GasLimit       uint64 `json:"gas_limit,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// SendResponse is the response body for POST /v1/send.
type SendResponse struct {
	From         string           `json:"from"`
	Nonce        uint64           `json:"nonce"`
	TxHash       string           `json:"tx_hash"`
	Replacements int              `json:"replacements"`
	Receipt      *ReceiptResponse `json:"receipt,omitempty"`
}

// ReceiptResponse is an optional mined receipt summary returned by /v1/send.
type ReceiptResponse struct {
	Status      uint64 `json:"status"`
	BlockNumber string `json:"block_number,omitempty"`
	GasUsed     uint64 `json:"gas_used,omitempty"`
}

