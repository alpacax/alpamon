package common

import (
	"strconv"

	"gopkg.in/go-playground/validator.v9"
)

// BaseHandler provides common functionality for all handlers
type BaseHandler struct {
	name      string
	commands  []string
	validator *validator.Validate
	Executor  CommandExecutor // Made public
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(name HandlerType, commands []CommandType, executor CommandExecutor) *BaseHandler {
	return &BaseHandler{
		name:      name.String(),
		commands:  CommandsToStrings(commands),
		validator: validator.New(),
		Executor:  executor,
	}
}

// Name returns the handler name
func (h *BaseHandler) Name() string {
	return h.name
}

// Commands returns the list of supported commands
func (h *BaseHandler) Commands() []string {
	return h.commands
}

// ValidateStruct validates a struct using struct tags
func (h *BaseHandler) ValidateStruct(s interface{}) error {
	return h.validator.Struct(s)
}

// Helper functions for common operations

// GetStringArg retrieves a string argument from the args map
func GetStringArg(args map[string]interface{}, key string, defaultValue string) string {
	if val, ok := args[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetIntArg retrieves an integer argument from the args map
func GetIntArg(args map[string]interface{}, key string, defaultValue int) int {
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultValue
}

// GetBoolArg retrieves a boolean argument from the args map
func GetBoolArg(args map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := args[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// GetStringSliceArg retrieves a string slice argument from the args map
func GetStringSliceArg(args map[string]interface{}, key string) []string {
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case []string:
			return v
		case []interface{}:
			var result []string
			for _, item := range v {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}
