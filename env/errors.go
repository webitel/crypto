package env

import "errors"

var (

	// NotFound reports that an environment key was not set.
	NotFound = errors.New("env: not found")

	// InvalidName is the base error for an invalid [Name]; test for it with [errors.Is].
	InvalidName = errors.New("env: invalid name")
)
