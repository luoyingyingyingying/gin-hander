package model

import (
	"time"
)

type Customer struct {
	ID        int       `gorm:"primaryKey;autoIncrement"`
	DeviceID  string    `gorm:"type:varchar(255)"`
	Enabled   bool      `gorm:"not null"`
	Title     string    `gorm:"type:varchar(30);unique"`
	CreatedAt time.Time `gorm:"not null;autoCreateTime"`
	UpdatedAt time.Time `gorm:"not null;autoUpdateTime"`
}

func (s *Customer) TableName() string {
	return "customer"
}
