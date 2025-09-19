package model

import (
	"fmt"

	"gorm.io/gorm"
)

func FetchAll[T any, ID any](db *gorm.DB, idFields string, getID func(*T) ID, callback func(*T) error, limit int) error {
	var (
		currentID ID
		err       error
		first     = true
		model     T
	)
	for {
		var r []*T
		query := db.Model(&model)
		if !first {
			query = query.Where(fmt.Sprintf("%s>?", idFields), currentID)
		}
		if err = query.Order(fmt.Sprintf("%s ASC", idFields)).Limit(limit).Find(&r).Error; err != nil {
			return err
		}
		for _, v := range r {
			if err = callback(v); err != nil {
				return err
			}
			currentID = getID(v)
		}
		first = false
		if len(r) < limit {
			return nil
		}
	}
}
