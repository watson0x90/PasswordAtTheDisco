package auth

import (
	"encoding/json"
	"fmt"
	"os"
)

// Role is an operator's authorization level.
type Role string

const (
	RoleAnalyst Role = "analyst" // redacted data only
	RoleLead    Role = "lead"    // may reveal cleartext (audit-logged)
)

func validRole(r Role) bool { return r == RoleAnalyst || r == RoleLead }

// User is a configured operator. PasswordHash is an argon2id PHC string.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         Role   `json:"role"`
}

// Users is the operator set, keyed by username.
type Users map[string]User

// LoadUsers reads a JSON array of users from path.
func LoadUsers(path string) (Users, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []User
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	users := make(Users, len(list))
	for _, u := range list {
		if u.Username == "" || u.PasswordHash == "" {
			return nil, fmt.Errorf("user entry missing username or password_hash")
		}
		if !validRole(u.Role) {
			return nil, fmt.Errorf("user %q has invalid role %q", u.Username, u.Role)
		}
		users[u.Username] = u
	}
	return users, nil
}

// a valid hash used to spend comparable time on unknown usernames, reducing the
// timing oracle for user enumeration.
var dummyHash = func() string {
	h, _ := HashPassword("not-a-real-password")
	return h
}()

// Authenticate verifies credentials, returning the user on success.
func (u Users) Authenticate(username, password string) (User, bool) {
	user, ok := u[username]
	if !ok {
		VerifyPassword(password, dummyHash) // equalize timing
		return User{}, false
	}
	if !VerifyPassword(password, user.PasswordHash) {
		return User{}, false
	}
	return user, true
}
