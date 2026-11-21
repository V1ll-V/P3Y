package server

import (
	"errors"
	"testing"

	"github.com/Autumn-27/norma/harness"
)

func TestRetryableWorkerModelErrorClassification(t *testing.T) {
	if !retryableWorkerModelError(harness.ReasonModelError, errors.New("stream reset: unexpected EOF")) {
		t.Fatal("transient stream error should be retryable")
	}
	if !retryableWorkerModelError(harness.ReasonModelError, errors.New("status 429: rate limit exceeded")) {
		t.Fatal("transient 429 rate limit should be retryable")
	}
	if retryableWorkerModelError(harness.ReasonModelError, errors.New(`anthropic: status 402: {"type":"error","error":{"type":"billing_error"}}`)) {
		t.Fatal("402 billing/quota error must not be retried")
	}
	if retryableWorkerModelError(harness.ReasonModelError, errors.New("status 401: invalid_api_key")) {
		t.Fatal("401 auth error must not be retried")
	}
	if retryableWorkerModelError(harness.ReasonModelError, errors.New("status 403: authentication_error")) {
		t.Fatal("403 auth error must not be retried")
	}
	if retryableWorkerModelError(harness.ReasonMaxTurns, errors.New("max turns")) {
		t.Fatal("non-model_error reason must not be retried")
	}
}
