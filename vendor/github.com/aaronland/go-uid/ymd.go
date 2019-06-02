package uid

import (
	"time"
)

type YMDUIDProvider struct {
	Provider
}

type YMDUID struct {
	UID
	date time.Time
}

func NewYMDUIDProvider() (Provider, error) {

	pr := YMDUIDProvider{}
	return &pr, nil
}

func (pr *YMDUIDProvider) UID(args ...interface{}) (UID, error) {

	date := time.Now()

	if len(args) == 1 {
		date = args[0].(time.Time)
	}

	return NewYMDUID(date)
}

func NewYMDUIDFromString(str_date string) (UID, error) {

	t, err := time.Parse("20060102", str_date)

	if err != nil {
		return nil, err
	}

	return NewYMDUID(t)
}

func NewYMDUID(date time.Time) (UID, error) {

	u := YMDUID{
		date: date,
	}

	return &u, nil
}

func (u *YMDUID) String() string {

	return u.date.Format("20060102")
}
