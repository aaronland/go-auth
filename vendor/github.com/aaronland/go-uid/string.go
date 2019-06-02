package uid

type StringUID struct {
	UID
	s string
}

func NewStringUID(s string) (UID, error) {

	u := StringUID{
		s: s,
	}

	return &u, nil
}

// where is UID() ?

func (u *StringUID) String() string {
	return u.s
}
