package repositories

import (
	"errors"
)

var ErrDBItemNotFound = errors.New("not found in DB")
