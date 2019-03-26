package account

import ()

type Membership interface {
	Id() string
	Identifiers() []string
	Details() []byte
	// Username() account.Username
	// Email() *mail.Address
	// Password() password.Password
	GetProperty(string) (interface{}, bool)
	SetProperty(string, interface{}) error
}

type MembershipDatabase interface {
	GetMembershipByIdentifier(string, string) (Membership, error)
	// GetMembershipByIdentifier(string, string, Membership) error
	AddMembership(Membership, ...string) error
	DeleteMembership(Membership) error
}

type Username interface {
	Name() string
	URISafeName() string
	String() string
}

// type OAuth2Database interface {}

type ErrNoMembership struct {
	error
}

func (e *ErrNoMembership) String() string {
	return "Membership does not exist"
}

func IsNotExist(e error) bool {

	switch e.(type) {
	case *ErrNoMembership:
		return true
	default:
		return false
	}
}
