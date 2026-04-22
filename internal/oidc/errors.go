package oidc

// AuthorizeError — RenderLocally=true when client_id/redirect_uri are
// untrusted and we must render /oidc/error instead of redirecting.
type AuthorizeError struct {
	Code          string
	Description   string
	RenderLocally bool
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

func ErrInvalidClient(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "invalid_client", Description: desc, RenderLocally: true}
}

func ErrInvalidRedirectURI(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "invalid_redirect_uri", Description: desc, RenderLocally: true}
}

func ErrInvalidRequest(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "invalid_request", Description: desc}
}

func ErrInvalidScope(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "invalid_scope", Description: desc}
}

func ErrUnsupportedResponseType(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "unsupported_response_type", Description: desc}
}

func ErrLoginRequired() *AuthorizeError {
	return &AuthorizeError{Code: "login_required", Description: "End-User authentication is required."}
}

func ErrServerError(desc string) *AuthorizeError {
	return &AuthorizeError{Code: "server_error", Description: desc, RenderLocally: true}
}
