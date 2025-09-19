package utils

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
)

type Worker interface {
	Serve(ctx context.Context) error
	Tag() string
}
type Creator[T Worker] func() (T, error)

type APIWorker interface {
	Worker
	Mount(r gin.IRouter)
}

type ErrorCode interface {
	Code() int
	error
}

type Ret[T any] struct {
	ErrNo int    `json:"err_no"`
	Msg   string `json:"msg"`
	Data  T      `json:"data"`
}

func ErrorRet[T any](err error) *Ret[T] {
	r := &Ret[T]{}
	return r.WithError(err)
}
func (r *Ret[T]) WithData(data T) *Ret[T] {
	r.Data = data
	return r
}
func (r *Ret[T]) WithError(err error) *Ret[T] {
	var val ErrorCode
	switch {
	case errors.As(err, &val):
		r.ErrNo = val.Code()
		r.Msg = val.Error()
	default:
		r.Msg = err.Error()
		r.ErrNo = -1
	}
	return r
}
func (r *Ret[T]) WithMsg(message string) *Ret[T] {
	r.Msg = message
	return r
}
func (r *Ret[T]) WithCode(code int) *Ret[T] {
	r.ErrNo = code
	return r
}
