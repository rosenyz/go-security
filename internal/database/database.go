package database

import (
	"go-security/config"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func Connect(cfg config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(cfg.DB.Dialect, cfg.DB.URL)
	return db, err
}
