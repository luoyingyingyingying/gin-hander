package auth

import (
	"crypto/rsa"

	"github.com/luoying/gin-hander/pkg/model"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type DeviceValidator interface {
	Validate(token *DeviceToken) (*model.Customer, error)
}

type defaultDeviceValidator struct {
	pk *rsa.PrivateKey
}

func DefaultDeviceValidator(pk *rsa.PrivateKey) DeviceValidator {
	return &defaultDeviceValidator{pk: pk}
}

func (v *defaultDeviceValidator) Validate(token *DeviceToken) (*model.Customer, error) {
	if err := token.Validate(); err != nil {
		return nil, err
	}

	if token.ValidateWithKey(v.pk) {
		return &model.Customer{
			DeviceID: token.ID,
		}, nil
	}
	return nil, StatusCodeBadToken
}

type dbDeviceValidator struct {
	db *gorm.DB
	defaultDeviceValidator
}

func DBDeviceValidator(db *gorm.DB, pk *rsa.PrivateKey) DeviceValidator {
	dv := &dbDeviceValidator{db: db}
	dv.pk = pk
	return dv
}

func (v *dbDeviceValidator) Validate(token *DeviceToken) (*model.Customer, error) {
	if err := token.Validate(); err != nil {
		return nil, errors.Wrap(err, "validate")
	}
	if !token.ValidateWithKey(v.pk) {
		return nil, StatusCodeBadToken
	}
	return v.findCustomer(token.ID)
}

func (v *dbDeviceValidator) findCustomer(deviceId string) (customer *model.Customer, err error) {
	customer = new(model.Customer)
	if err = v.db.Where(&model.Customer{
		DeviceID: deviceId,
		Enabled:  true,
	}).First(customer).Error; err != nil {
		return nil, err
	}
	return customer, err
}
