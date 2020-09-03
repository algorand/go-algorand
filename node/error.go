package node

// Catchpoint already in progress error

// CatchpointAlreadyInProgressError indicates that the requested catchpoint is already running
type CatchpointAlreadyInProgressError struct {
	message string
}

// MakeCatchpointAlreadyInProgressError creates the error
func MakeCatchpointAlreadyInProgressError(text string) *CatchpointAlreadyInProgressError {
	return &CatchpointAlreadyInProgressError{
		message: text,
		}
}

// Error satisfies builtin interface `error`
func (e *CatchpointAlreadyInProgressError) Error() string {
	return e.message
}

// Catchpoint unable to start error

// CatchpointUnableToStartError indicates that the requested catchpoint cannot be started
type CatchpointUnableToStartError struct {
	message string
}

// MakeCatchpointUnableToStartError creates the error
func MakeCatchpointUnableToStartError(text string) *CatchpointUnableToStartError {
	return &CatchpointUnableToStartError{
		message: text,
	}
}

// Error satisfies builtin interface `error`
func (e *CatchpointUnableToStartError) Error() string {
	return e.message
}
