package updater

import "errors"

// ErrorClass names why a pinned upgrade failed, in a form the console can
// group on without parsing messages. The values are part of the upgrade
// report and must stay stable.
type ErrorClass string

const (
	ClassSignatureInvalid  ErrorClass = "signature_invalid"
	ClassDigestMismatch    ErrorClass = "digest_mismatch"
	ClassDownloadFailed    ErrorClass = "download_failed"
	ClassSwapFailed        ErrorClass = "swap_failed"
	ClassHealthCheckFailed ErrorClass = "health_check_failed"
	ClassPackageManager    ErrorClass = "package_manager"

	// ClassKeysUnavailable marks the refusal before any download when this
	// build's compiled-in release key bundle is empty: this build carries no
	// release signing keys, so a pinned upgrade cannot be verified. Distinct
	// from ClassSignatureInvalid, which means a signature was checked and did
	// not verify; here there was no key to check one against.
	ClassKeysUnavailable ErrorClass = "keys_unavailable"

	ClassUnknown ErrorClass = "unknown"
)

// ClassifiedError carries an ErrorClass alongside the underlying error.
type ClassifiedError struct {
	Class ErrorClass
	Err   error
}

func (e *ClassifiedError) Error() string { return string(e.Class) + ": " + e.Err.Error() }

func (e *ClassifiedError) Unwrap() error { return e.Err }

// Classify wraps err with class. A nil err stays nil, and an error that is
// already classified keeps its original class.
func Classify(class ErrorClass, err error) error {
	if err == nil {
		return nil
	}
	var ce *ClassifiedError
	if errors.As(err, &ce) {
		return err
	}
	return &ClassifiedError{Class: class, Err: err}
}

// ClassOf returns the class of err: "" for nil, ClassUnknown for an error no
// step classified.
func ClassOf(err error) ErrorClass {
	if err == nil {
		return ""
	}
	var ce *ClassifiedError
	if errors.As(err, &ce) {
		return ce.Class
	}
	return ClassUnknown
}
