package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luoying/gin-hander/pkg/model"
	"github.com/luoying/gin-hander/pkg/utils"
)

const (
	keyCurrentDevice = "__mod_auth_current_device"
)

func ReadCurrentDevice(validator DeviceValidator, c *gin.Context) (*model.Customer, error) {
	token := &DeviceToken{}
	var err error
	if err = c.ShouldBindHeader(token); err != nil {
		return nil, StatusCodeTokenRequired
	}
	return validator.Validate(token)
}

func CurrentDeviceMiddleware(validator DeviceValidator) gin.HandlerFunc {
	return func(context *gin.Context) {
		device, err := ReadCurrentDevice(validator, context)
		if err != nil {
			context.AbortWithStatusJSON(http.StatusForbidden, utils.ErrorRet[any](err))
			return
		}
		context.Set(keyCurrentDevice, device)
	}
}

func CurrentDevice(c *gin.Context) (*model.Customer, error) {
	val, ok := c.Get(keyCurrentDevice)
	if !ok {
		return nil, StatusCodeDeviceRequired
	}
	if device, ok := val.(*model.Customer); ok {
		return device, nil
	} else {
		return nil, StatusCodeBadDevice
	}
}
