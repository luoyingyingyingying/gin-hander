package utils

import (
	"errors"
	"sync/atomic"
)

type Iterator[T any] interface {
	Next() (T, error)
}

// Done Iterator completed
var Done = errors.New("done")

type empty[T any] struct {
}

func (e empty[T]) Next() (t T, err error) {
	return t, Done
}

// Empty returns empty Iterator[T]
func Empty[T any]() Iterator[T] {
	return empty[T]{}
}

type IterFunc[T any] func(int) (T, error)
type WrapFunc[T any, R any] func(T) (R, error)
type simpleIter[T any] struct {
	cache []T
	size  int
	index int
}

func SimpleIter[T any](items []T) Iterator[T] {
	return &simpleIter[T]{cache: items, size: len(items)}
}

func (s *simpleIter[T]) Next() (t T, err error) {
	if s.index >= s.size {
		return t, Done
	}
	t = s.cache[s.index]
	s.index++
	return t, err
}
func Iter[T any](data []T) Iterator[T] {
	return &simpleIter[T]{
		cache: data,
		size:  len(data),
		index: 0,
	}
}

type iterChain[T any] struct {
	its Iterator[Iterator[T]]
	cur Iterator[T]
}

func (chain *iterChain[T]) Next() (t T, err error) {
	for {
		if chain.cur == nil {
			if chain.cur, err = chain.its.Next(); err != nil {
				return
			}
		}
		if t, err = chain.cur.Next(); err == Done {
			chain.cur = nil
			continue
		} else {
			return
		}
	}
}
func SimpleChain[T any](its ...Iterator[T]) Iterator[T] {
	return &iterChain[T]{its: Iter(its)}
}

// Chain Iterator chain
func Chain[T any](its Iterator[Iterator[T]]) Iterator[T] {
	return &iterChain[T]{its: its}
}

type forLoopIter[T any] struct {
	meth func(int) (T, error)
	cur  int
}

func (loop *forLoopIter[T]) Next() (T, error) {
	ret, err := loop.meth(loop.cur)
	loop.cur++
	return ret, err
}

type wrapIter[T any, R any] struct {
	it   Iterator[T]
	wrap WrapFunc[T, R]
}

func Wrapper[T any, R any](it Iterator[T], wrap WrapFunc[T, R]) Iterator[R] {
	return &wrapIter[T, R]{it: it, wrap: wrap}
}

func (w *wrapIter[T, R]) Next() (r R, err error) {
	ret, err := w.it.Next()
	if err != nil {
		return
	}
	return w.wrap(ret)
}
func Lazy[T any](meth IterFunc[[]T]) Iterator[T] {
	loop := &forLoopIter[[]T]{meth: meth}
	var wrap Iterator[Iterator[T]] = &wrapIter[[]T, Iterator[T]]{
		it:   loop,
		wrap: func(rows []T) (Iterator[T], error) { return Iter(rows), nil },
	}
	return &iterChain[T]{its: wrap}
}

type filterIter[T any] struct {
	it       Iterator[T]
	doFilter func(T) bool
}

func (f *filterIter[T]) Next() (T, error) {
	for {
		if ret, err := f.it.Next(); err != nil {
			return ret, err
		} else if !f.doFilter(ret) {
			continue
		} else {
			return ret, err
		}
	}
}
func WithFilter[T any](it Iterator[T], ms ...func(T) bool) Iterator[T] {
	return &filterIter[T]{it: it, doFilter: func(val T) bool { return AllMatch(val, ms...) }}
}

func AllMatch[T any](val T, ms ...func(T) bool) bool {
	for _, m := range ms {
		if !m(val) {
			return false
		}
	}
	return true
}
func All[T any](items []T, m func(T) bool) bool {
	for _, item := range items {
		if !m(item) {
			return false
		}
	}
	return true
}
func Any[T any](items []T, m func(T) bool) bool {
	for _, item := range items {
		if m(item) {
			return true
		}
	}
	return false
}
func Map[T any, R any](items []T, m func(T) (R, error)) (ret []R, err error) {
	ret = make([]R, len(items))
	for i, item := range items {
		if ret[i], err = m(item); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func Apply[T any](val T, ms ...func(T) (T, error)) (ret T, err error) {
	ret = val
	for _, m := range ms {
		if ret, err = m(ret); err != nil {
			return
		}
	}
	return
}
func Filter[T any](items []T, fn func(T) bool) []T {
	ret := make([]T, len(items))
	cur := 0
	for _, item := range items {
		if fn(item) {
			ret[cur] = item
			cur += 1
		}
	}
	return ret[0:cur]
}
func FindIter[T any](it Iterator[T], fn func(T) (bool, error)) (T, error) {
	for {
		if item, err := it.Next(); err != nil {
			return item, err
		} else if ok, err := fn(item); err != nil || ok {
			return item, err
		}
	}
}

type Enumerate[T any] struct {
	it     Iterator[T]
	cursor int
}

func NewEnumerate[T any](it Iterator[T]) *Enumerate[T] {
	return &Enumerate[T]{it: it}
}

func (receiver *Enumerate[T]) Next() (int, T, error) {
	ret, err := receiver.it.Next()
	if err != nil {
		return -1, ret, err
	}
	defer func() {
		receiver.cursor += 1
	}()
	return receiver.cursor, ret, err
}
func Reduce[T any](it Iterator[T], op func(a, b T) (T, error), initializer func() (T, error)) (T, error) {
	var initMeth func() (T, error)
	if initializer != nil {
		initMeth = initializer
	} else {
		initMeth = it.Next
	}
	val, err := initMeth()
	if err != nil {
		return val, err
	}
	for {
		if r, err := it.Next(); err != nil {
			if err == Done {
				return val, nil
			}
			return r, err
		} else if val, err = op(val, r); err != nil {
			return val, err
		}
	}
}

type sillyRange[T any] struct {
	initialized int32
	lastValue   T
	initializer func() (T, error)
	plus        func(a T) (T, error)
}

func (s *sillyRange[T]) Next() (T, error) {
	var err error
	if atomic.CompareAndSwapInt32(&s.initialized, 0, 1) {
		s.lastValue, err = s.initializer()
		return s.lastValue, err
	}
	s.lastValue, err = s.plus(s.lastValue)
	return s.lastValue, err
}

func SillyRange[T any](initializer func() (T, error), plus func(a T) (T, error)) Iterator[T] {
	return &sillyRange[T]{initializer: initializer, plus: plus}
}
