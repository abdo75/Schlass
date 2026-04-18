package oidc

// AuthorizeError represents an /authorize failure. RenderLocally=true means
// we cannot safely redirect (client_id or redirect_uri untrusted) and must
// render /oidc/error. RenderLocally=false means we redirect back to the
// registered redirect_uri with ?error=...&state=...
type AuthorizeError struct {
	Code          string // OAuth error code
	Description   string
	RenderLocally bool
}

func (e *AuthorizeError) Error() string { return e.Code + ": " + e.Description }

// Factories — spec-canonical codes per RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6.

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
