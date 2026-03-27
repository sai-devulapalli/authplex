package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOk(t *testing.T) {
	r := Ok(42)

	assert.True(t, r.IsOk())
	assert.False(t, r.IsErr())

	val, err := r.Unwrap()
	assert.Equal(t, 42, val)
	assert.Nil(t, err)
}

func TestErr(t *testing.T) {
	appErr := New(ErrNotFound, "not found")
	r := Err[int](appErr)

	assert.False(t, r.IsOk())
	assert.True(t, r.IsErr())

	val, err := r.Unwrap()
	assert.Equal(t, 0, val)
	assert.Equal(t, appErr, err)
}

func TestResult_Value(t *testing.T) {
	t.Run("ok result returns value", func(t *testing.T) {
		r := Ok("hello")
		assert.Equal(t, "hello", r.Value())
	})

	t.Run("error result returns zero value", func(t *testing.T) {
		r := Err[string](New(ErrInternal, "fail"))
		assert.Equal(t, "", r.Value())
	})
}

func TestResult_Error(t *testing.T) {
	t.Run("ok result returns nil error", func(t *testing.T) {
		r := Ok(42)
		assert.Nil(t, r.Error())
	})

	t.Run("error result returns AppError", func(t *testing.T) {
		appErr := New(ErrBadRequest, "invalid")
		r := Err[int](appErr)
		assert.Equal(t, appErr, r.Error())
	})
}

func TestResult_Map(t *testing.T) {
	t.Run("maps ok value", func(t *testing.T) {
		r := Ok(5)
		mapped := r.Map(func(v int) int { return v * 2 })

		assert.True(t, mapped.IsOk())
		assert.Equal(t, 10, mapped.Value())
	})

	t.Run("propagates error", func(t *testing.T) {
		appErr := New(ErrInternal, "fail")
		r := Err[int](appErr)
		mapped := r.Map(func(v int) int { return v * 2 })

		assert.True(t, mapped.IsErr())
		assert.Equal(t, appErr, mapped.Error())
	})
}

func TestResult_FlatMap(t *testing.T) {
	t.Run("flatmaps ok value", func(t *testing.T) {
		r := Ok(10)
		result := r.FlatMap(func(v int) Result[int] {
			if v > 5 {
				return Ok(v + 1)
			}
			return Err[int](New(ErrBadRequest, "too small"))
		})

		assert.True(t, result.IsOk())
		assert.Equal(t, 11, result.Value())
	})

	t.Run("flatmap returns error from function", func(t *testing.T) {
		r := Ok(3)
		result := r.FlatMap(func(v int) Result[int] {
			if v > 5 {
				return Ok(v + 1)
			}
			return Err[int](New(ErrBadRequest, "too small"))
		})

		assert.True(t, result.IsErr())
		assert.Equal(t, ErrBadRequest, result.Error().Code)
	})

	t.Run("propagates existing error", func(t *testing.T) {
		appErr := New(ErrInternal, "original")
		r := Err[int](appErr)
		result := r.FlatMap(func(v int) Result[int] {
			return Ok(v + 1)
		})

		assert.True(t, result.IsErr())
		assert.Equal(t, appErr, result.Error())
	})
}

func TestResult_OrElse(t *testing.T) {
	t.Run("returns value when ok", func(t *testing.T) {
		r := Ok(42)
		assert.Equal(t, 42, r.OrElse(0))
	})

	t.Run("returns default when error", func(t *testing.T) {
		r := Err[int](New(ErrNotFound, "missing"))
		assert.Equal(t, -1, r.OrElse(-1))
	})
}

func TestMapTo(t *testing.T) {
	t.Run("maps to different type", func(t *testing.T) {
		r := Ok(42)
		mapped := MapTo(r, func(v int) string { return "value" })

		assert.True(t, mapped.IsOk())
		assert.Equal(t, "value", mapped.Value())
	})

	t.Run("propagates error to different type", func(t *testing.T) {
		appErr := New(ErrInternal, "fail")
		r := Err[int](appErr)
		mapped := MapTo(r, func(v int) string { return "value" })

		assert.True(t, mapped.IsErr())
		assert.Equal(t, appErr, mapped.Error())
	})
}

func TestResult_WithStruct(t *testing.T) {
	type User struct {
		ID   string
		Name string
	}

	r := Ok(User{ID: "1", Name: "Alice"})
	assert.True(t, r.IsOk())
	assert.Equal(t, "Alice", r.Value().Name)
}

func TestResult_WithSlice(t *testing.T) {
	r := Ok([]int{1, 2, 3})
	assert.True(t, r.IsOk())
	assert.Len(t, r.Value(), 3)
}
