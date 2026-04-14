package model

// ValidationError represents a general input validation failure.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// PasswordPolicyError represents a password that doesn't meet policy requirements.
type PasswordPolicyError struct {
	Message string
}

func (e *PasswordPolicyError) Error() string {
	return e.Message
}
