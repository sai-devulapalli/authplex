package errors

// Result represents a computation that either succeeds with a value of type T
// or fails with an AppError. This provides a type-safe alternative to Go's
// (T, error) pattern while enforcing that errors are always AppError.
type Result[T any] struct {
	value T
	err   *AppError
}

// Ok creates a successful Result containing the given value.
func Ok[T any](value T) Result[T] {
	return Result[T]{value: value}
}

// Err creates a failed Result containing the given error.
func Err[T any](err *AppError) Result[T] {
	return Result[T]{err: err}
}

// IsOk returns true if the Result contains a success value.
func (r Result[T]) IsOk() bool {
	return r.err == nil
}

// IsErr returns true if the Result contains an error.
func (r Result[T]) IsErr() bool {
	return r.err != nil
}

// Unwrap returns the value and error. This is the primary Go-idiomatic
// access method for Result values.
func (r Result[T]) Unwrap() (T, *AppError) {
	return r.value, r.err
}

// Value returns the success value. Returns the zero value of T if the Result is an error.
func (r Result[T]) Value() T {
	return r.value
}

// Error returns the AppError, or nil if the Result is successful.
func (r Result[T]) Error() *AppError {
	return r.err
}

// Map transforms the success value using the provided function.
// If the Result is an error, the error is propagated unchanged.
func (r Result[T]) Map(fn func(T) T) Result[T] {
	if r.IsErr() {
		return r
	}
	return Ok(fn(r.value))
}

// FlatMap transforms the success value using a function that returns a Result.
// If the Result is an error, the error is propagated unchanged.
func (r Result[T]) FlatMap(fn func(T) Result[T]) Result[T] {
	if r.IsErr() {
		return r
	}
	return fn(r.value)
}

// OrElse returns the success value or the provided default if the Result is an error.
func (r Result[T]) OrElse(defaultValue T) T {
	if r.IsErr() {
		return defaultValue
	}
	return r.value
}

// MapTo transforms a Result[T] into a Result of a different type using a function.
// This is a standalone function because Go methods cannot have additional type parameters.
func MapTo[T any, U any](r Result[T], fn func(T) U) Result[U] {
	if r.IsErr() {
		return Err[U](r.err)
	}
	return Ok(fn(r.value))
}
