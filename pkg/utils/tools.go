package utils

import (
	"context"
	"errors"
	"sync"
	"time"
)

var NotFound = errors.New("not found")

func Retry[T any](fn func() (T, error), times int, delay time.Duration) (T, error) {
	var (
		ret T
		err error
	)
	for i := 0; i < times+1; i++ {
		ret, err = fn()
		if err == nil {
			break
		}
		time.Sleep(delay)
	}
	return ret, err
}

func Find[T any](items []T, fn func(T) bool) (int, T, error) {
	var (
		idx = -1
		ret T
		err = NotFound
	)
	for i, item := range items {
		if fn(item) {
			idx, ret, err = i, item, nil
			break
		}
	}
	return idx, ret, err
}
func ForEach[T any](items []T, fn func(T) error) error {
	var err error
	for _, item := range items {
		if err = fn(item); err != nil {
			return err
		}
	}
	return err
}
func WaitAll(ctx context.Context, fs ...func(ctx context.Context)) {
	wg := &sync.WaitGroup{}
	for _, fn := range fs {
		wg.Add(1)
		fn := fn
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	wg.Wait()
}
