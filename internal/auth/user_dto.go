package auth

import "github.com/abdo75/Schlass/internal/users"

// userDTO converts a users.User to the JSON shape returned by auth + admin
// endpoints. Defined here so handler.go can call it; the canonical copy lives
// in internal/users/ for the users handler.
func userDTO(u *users.User) map[string]any {
	return map[string]any{
		"id":                    u.ID.String(),
		"email":                 u.Email,
		"role":                  u.Role,
		"status":                u.Status,
		"force_password_change": u.ForcePasswordChange,
		"created_at":            u.CreatedAt,
		"updated_at":            u.UpdatedAt,
		"totp_enrolled_at":      u.TOTPEnrolledAt,
		"last_login_at":         u.LastLoginAt,
	}
}
