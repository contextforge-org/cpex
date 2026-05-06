// Location: ./go/cpex/errors.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Sentinel errors for FFI return-code classification.
//
// The libcpex_ffi C API returns int codes (0 = success, negative =
// failure). Each negative code maps to a stable sentinel error here —
// callers can use `errors.Is(err, ErrCpexTimeout)` to handle specific
// failure modes (retry on timeout, abort on panic, etc.) instead of
// regex-matching opaque "invoke failed" strings.

package cpex

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the FFI wrapper. Compare with `errors.Is`.
// All errors returned from PluginManager / BackgroundTasks methods that
// originated in a non-zero FFI return code wrap one of these.
var (
	// ErrCpexInvalidHandle: the manager handle is null or has been
	// shutdown. Trying to use a manager after Shutdown produces this.
	ErrCpexInvalidHandle = errors.New("cpex: invalid handle (manager null or shutdown)")

	// ErrCpexInvalidInput: caller-supplied input was malformed — bad
	// UTF-8, null pointer where data was required, oversized buffer,
	// unknown payload type. Caller bug; fix the input and retry.
	ErrCpexInvalidInput = errors.New("cpex: invalid input")

	// ErrCpexParse: parse / deserialize step failed (YAML config,
	// MessagePack payload, MessagePack extensions). Caller bug; fix
	// the data shape and retry.
	ErrCpexParse = errors.New("cpex: parse / deserialize failed")

	// ErrCpexPipeline: pipeline / lifecycle step failed — load_config
	// returned Err, initialize failed, or a plugin signalled a
	// runtime failure that wasn't a timeout or panic.
	ErrCpexPipeline = errors.New("cpex: pipeline / lifecycle error")

	// ErrCpexSerialize: result serialization failed after the pipeline
	// ran successfully. Usually OOM on rmp_serde::to_vec_named or an
	// unserializable JSON value. Rare; not retryable on its own.
	ErrCpexSerialize = errors.New("cpex: result serialize failed")

	// ErrCpexTimeout: wall-clock timeout exceeded inside the FFI
	// boundary. The plugin is likely CPU-bound or blocking the OS
	// thread without yielding (per-plugin tokio timeouts can't catch
	// non-cooperative work). Caller may retry but probably wants to
	// disable the offending plugin first.
	ErrCpexTimeout = errors.New("cpex: wall-clock timeout exceeded")

	// ErrCpexPanic: a plugin panicked across the FFI boundary; the
	// panic was caught (preventing UB / process abort) but the
	// invocation is lost. Same plugin will likely panic again.
	ErrCpexPanic = errors.New("cpex: plugin panicked at FFI boundary")
)

// errorFromRC maps an FFI return code to a typed error. `op` is included
// in the wrapped message so the caller can tell which operation failed
// without losing the sentinel for `errors.Is` checks.
func errorFromRC(rc int, op string) error {
	switch rc {
	case rcOK:
		return nil
	case rcInvalidHandle:
		return fmt.Errorf("%s: %w", op, ErrCpexInvalidHandle)
	case rcInvalidInput:
		return fmt.Errorf("%s: %w", op, ErrCpexInvalidInput)
	case rcParseError:
		return fmt.Errorf("%s: %w", op, ErrCpexParse)
	case rcPipelineError:
		return fmt.Errorf("%s: %w", op, ErrCpexPipeline)
	case rcSerializeError:
		return fmt.Errorf("%s: %w", op, ErrCpexSerialize)
	case rcTimeout:
		return fmt.Errorf("%s: %w", op, ErrCpexTimeout)
	case rcPanic:
		return fmt.Errorf("%s: %w", op, ErrCpexPanic)
	default:
		// Unknown code — wrap a generic error including the rc so
		// the caller can at least see the raw value.
		return fmt.Errorf("%s: cpex: unknown FFI return code %d", op, rc)
	}
}
