package model

// ValidationError represents a general input validation failure.
//
// Field and Code are optional and were added in Sprint 6b to support the
// admin settings handlers, which map typed validation failures to i18n keys
// on the frontend (backend returns stable codes, SPA translates). Legacy
// callers that only set Message continue to work unchanged — handlers that
// care about Field/Code read them explicitly.
type ValidationError struct {
	Message string
	Field   string
	Code    string
}

func (e *ValidationError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return e.Code
	}
	return "validation error"
}

// PasswordPolicyError represents a password that doesn't meet policy requirements.
type PasswordPolicyError struct {
	Message string
}

func (e *PasswordPolicyError) Error() string {
	return e.Message
}
