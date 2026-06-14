package storage

import (
	"database/sql"
	"errors"

	"secret-service/internal/errs"
)

func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errs.ErrNotFound
	}
	return err
}
