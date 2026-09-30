//go:build linux && (amd64 || arm64)

// Package pam provides Linux-PAM binding without cgo. It is not an
// authentication policy, credential provider, or cancellable worker.
package pam

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/bnema/purego"
)

var (
	ErrClosed          = errors.New("pam: library or transaction is closed")
	ErrBusy            = errors.New("pam: active transactions prevent library close")
	ErrInvalidArgument = errors.New("pam: invalid argument")
)

// Error preserves the native status without retaining or logging credentials.
type Error struct {
	Operation string
	Status    Status
}

func (e *Error) Error() string {
	return fmt.Sprintf("pam: %s failed (status %d)", e.Operation, e.Status)
}
func statusError(operation string, status Status) error {
	if status == Success {
		return nil
	}
	return &Error{Operation: operation, Status: status}
}

// Library owns loader references. The zero value is closed. Do not copy it.
// All operations on a Library and its Transactions must be serialized by one caller/worker.
// Native calls are synchronous, may block, and have no cancellation guarantee.
type Library struct {
	calls                 libraryFunctions
	memory                nativeMemory
	pamHandle, libcHandle uintptr
	active                int
	closed                bool
}

// Transaction owns a PAM handle and native argument storage until End returns.
// Do not copy a Transaction. End must be called exactly once after successful
// Start; it consumes the transaction even if pam_end reports an error.
type Transaction struct {
	library *Library
	handle  unsafe.Pointer
	storage []unsafe.Pointer
	last    Status
	ended   bool
	bridge  *conversationState
}

// Start requires an explicit service and native conversation; user may be empty
// (passed as NULL so PAM may prompt). It never authenticates. No service is
// installed by this library. NativeConversation is a trusted unsafe boundary.
func (l *Library) Start(service, user string, conversation NativeConversation) (*Transaction, error) {
	return l.start(service, user, conversation, nil)
}

func (l *Library) start(service, user string, conversation NativeConversation, bridge *conversationState) (*Transaction, error) {
	if l == nil || l.closed || l.calls == nil || l.memory == nil {
		return nil, ErrClosed
	}
	if service == "" || strings.ContainsRune(service, '\x00') || strings.ContainsRune(user, '\x00') || conversation.Function == 0 {
		return nil, ErrInvalidArgument
	}
	t := &Transaction{library: l, last: Abort, bridge: bridge}
	keep := func(p unsafe.Pointer, err error) (unsafe.Pointer, error) {
		if err == nil {
			t.storage = append(t.storage, p)
		}
		return p, err
	}
	servicePtr, err := keep(nativeCString(l.memory, service))
	if err != nil {
		return nil, err
	}
	var userPtr unsafe.Pointer
	if user != "" {
		userPtr, err = keep(nativeCString(l.memory, user))
		if err != nil {
			t.release()
			return nil, err
		}
	}
	convPtr, err := keep(l.memory.alloc(unsafe.Sizeof(nativeConversation{})))
	if err != nil {
		t.release()
		return nil, err
	}
	if bridge == nil {
		*(*nativeConversation)(convPtr) = nativeConversation(conversation)
	} else {
		// Write opaque cookie bits without converting them to a Go pointer.
		*(*nativeCookieConversation)(convPtr) = nativeCookieConversation{Function: conversation.Function, Cookie: bridge.token}
	}
	output, err := keep(l.memory.alloc(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		t.release()
		return nil, err
	}
	status := l.calls.Start(servicePtr, userPtr, convPtr, output)
	if status != Success {
		// pam_start(3): output is undefined on failure. Never read it or
		// call pam_end with it; libpam owns its failed-start cleanup.
		t.release()
		return nil, statusError("start", status)
	}
	t.handle = *(*unsafe.Pointer)(output)
	if t.handle == nil {
		t.release()
		return nil, errors.New("pam: start succeeded with a NULL handle")
	}
	t.last = Success
	l.active++
	return t, nil
}

func (t *Transaction) valid() bool {
	return t != nil && !t.ended && t.library != nil && t.handle != nil
}

// Authenticate returns an error for every status other than PAM_SUCCESS.
// Success here is NOT an account authorization decision; call AcctMgmt too.
func (t *Transaction) Authenticate(flags Flags) error {
	if !t.valid() {
		return ErrClosed
	}
	if flags & ^(Silent|DisallowNullAuthtok) != 0 {
		t.last = SystemErr
		return ErrInvalidArgument
	}
	t.last = t.library.calls.Authenticate(t.handle, flags)
	return statusError("authenticate", t.last)
}

// AcctMgmt fails closed, including PAM_NEW_AUTHTOK_REQD and PAM_INCOMPLETE.
func (t *Transaction) AcctMgmt(flags Flags) error {
	if !t.valid() {
		return ErrClosed
	}
	if flags & ^(Silent|DisallowNullAuthtok) != 0 {
		t.last = SystemErr
		return ErrInvalidArgument
	}
	t.last = t.library.calls.AcctMgmt(t.handle, flags)
	return statusError("acct_mgmt", t.last)
}

// End passes the last operation's status to pam_end and releases native storage
// only after that call returns. A second End returns ErrClosed, never calls C.
func (t *Transaction) End() error {
	if !t.valid() {
		return ErrClosed
	}
	t.ended = true
	status := t.library.calls.End(t.handle, t.last)
	t.handle = nil
	t.release()
	t.library.active--
	return statusError("end", status)
}

func (t *Transaction) release() {
	if t.bridge != nil {
		t.bridge.retire()
		t.bridge = nil
	}
	for i := len(t.storage) - 1; i >= 0; i-- {
		t.library.memory.free(t.storage[i])
	}
	t.storage = nil
}

// Close refuses to unload symbols still needed by live transactions.
func (l *Library) Close() error {
	if l == nil || l.closed || l.calls == nil {
		return ErrClosed
	}
	if l.active != 0 {
		return ErrBusy
	}
	l.closed = true
	var err error
	if l.pamHandle != 0 {
		err = errorsWithClose(err, l.pamHandle)
	}
	if l.libcHandle != 0 {
		err = errorsWithClose(err, l.libcHandle)
	}
	return err
}

func errorsWithClose(err error, handle uintptr) error {
	return errors.Join(err, purego.Dlclose(handle))
}
