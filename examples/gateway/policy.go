package gateway

import "path"

// User is the principal opening a session.
type User struct {
	Name  string
	Admin bool
}

// Decision is the outcome of policy evaluation.
type Decision struct {
	Allowed  bool
	PolicyID string
}

// Policy IDs recorded on the authorize span.
const (
	PolicyDenyProdNonAdmin = "deny-prod-nonadmin"
	PolicyAllowAdmin       = "allow-admin"
	PolicyAllowDefault     = "allow-default"
)

// Evaluate is the toy policy: deny any host matching "prod-*" for non-admins.
func Evaluate(u User, host string) Decision {
	if ok, _ := path.Match("prod-*", host); ok {
		if !u.Admin {
			return Decision{Allowed: false, PolicyID: PolicyDenyProdNonAdmin}
		}
		return Decision{Allowed: true, PolicyID: PolicyAllowAdmin}
	}
	return Decision{Allowed: true, PolicyID: PolicyAllowDefault}
}
