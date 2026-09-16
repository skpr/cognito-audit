package types

import "time"

// LastLogin is the JSON payload that is stored in the custom user pool
// attribute every time a user successfully authenticates.
type LastLogin struct {
	// Time the user last logged in, in RFC3339 format.
	Time time.Time `json:"time"`
	// ClientID of the app client that was used to authenticate.
	ClientID string `json:"client_id,omitempty"`
}
