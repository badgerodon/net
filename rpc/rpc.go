package rpc

import (
	"encoding/json"
)

type (
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	Request struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
		ID     int               `json:"id"`
	}
	Response struct {
		Result *json.RawMessage `json:"result"`
		Error  *Error           `json:"error,omitempty"`
		ID     int              `json:"id"`
	}
)
