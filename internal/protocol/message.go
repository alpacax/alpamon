package protocol

import (
	"encoding/json"
	"time"
)

// MessageType defines the type of protocol message
type MessageType string

const (
	MessageTypeCommand   MessageType = "command"
	MessageTypeQuit      MessageType = "quit"
	MessageTypeReconnect MessageType = "reconnect"
	MessageTypePing      MessageType = "ping"
)

// Message is the base protocol message envelope received from the server
type Message struct {
	Query   MessageType     `json:"query"`
	Command *Command        `json:"command,omitempty"`
	Reason  string          `json:"reason,omitempty"`
	Raw     json.RawMessage `json:"-"` // Original raw message for debugging
}

// Response represents a response message to send back to the server
type Response struct {
	Query string `json:"query"`
}

// CommandResponse represents a command execution result
type CommandResponse struct {
	Success     bool    `json:"success"`
	Result      string  `json:"result"`
	ElapsedTime float64 `json:"elapsed_time"`
}

// PingResponse represents a ping response
type PingResponse struct {
	Query     string    `json:"query"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// NewPingResponse creates a new ping response
func NewPingResponse() *PingResponse {
	return &PingResponse{
		Query:     "ping",
		Timestamp: time.Now(),
	}
}

// NewCommandResponse creates a new command response
func NewCommandResponse(success bool, result string, elapsed float64) *CommandResponse {
	return &CommandResponse{
		Success:     success,
		Result:      result,
		ElapsedTime: elapsed,
	}
}

// ParseMessage parses a raw JSON message into a Message struct
func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	msg.Raw = data
	return &msg, nil
}
