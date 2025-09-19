package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type APIService[P any, T any] interface {
	Invoke(param P, c *gin.Context) (T, error)
}

func execApiService[P any, T any](param P, service APIService[P, T], c *gin.Context) {
	ret, err := service.Invoke(param, c)
	if c.IsAborted() {
		return
	}
	var r = &Ret[T]{}
	if err != nil {
		r.WithError(err)
	} else {
		r.WithData(ret)
	}
	c.JSON(http.StatusOK, r)
}

func ExecApiService[P any, T any](param P, service APIService[P, T]) gin.HandlerFunc {
	return func(c *gin.Context) {
		execApiService(param, service, c)
	}
}

type APIServiceCreator[P any, T any] func() APIService[P, T]

func CallApiService[P any, T any](param P, sf APIServiceCreator[P, T]) gin.HandlerFunc {
	return func(c *gin.Context) {
		s := sf()
		execApiService[P, T](param, s, c)
	}
}
func InvokeApiService[P any, T any, ST APIService[P, T]](param P) gin.HandlerFunc {
	return CallApiService(param, func() APIService[P, T] {
		var it ST
		return it
	})
}
