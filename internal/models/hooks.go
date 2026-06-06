package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BeforeCreate assigns a v4 UUID primary key when the caller did not set one.
// Centralising this on Base means every model gets server-side ID generation
// without depending on a Postgres extension (so the SQLite test path works
// too).
func (b *Base) BeforeCreate(*gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}
