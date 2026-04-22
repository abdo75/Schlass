package model

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

type PasswordPolicyError struct {
	Message string
}

func (e *PasswordPolicyError) Error() string {
	return e.Message
}
