//go:build linux && (amd64 || arm64)

package pam

import (
	"fmt"
	"unsafe"

	"github.com/bnema/purego"
)

// libraryFunctions is the test seam; tests use Mockery, never replace functions.
type libraryFunctions interface {
	Start(service, user, conversation, output unsafe.Pointer) Status
	Authenticate(handle unsafe.Pointer, flags Flags) Status
	AcctMgmt(handle unsafe.Pointer, flags Flags) Status
	End(handle unsafe.Pointer, status Status) Status
}

type boundFunctions struct {
	start        func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) Status
	authenticate func(unsafe.Pointer, Flags) Status
	acctMgmt     func(unsafe.Pointer, Flags) Status
	end          func(unsafe.Pointer, Status) Status
}

func (b *boundFunctions) Start(s, u, c, o unsafe.Pointer) Status        { return b.start(s, u, c, o) }
func (b *boundFunctions) Authenticate(h unsafe.Pointer, f Flags) Status { return b.authenticate(h, f) }
func (b *boundFunctions) AcctMgmt(h unsafe.Pointer, f Flags) Status     { return b.acctMgmt(h, f) }
func (b *boundFunctions) End(h unsafe.Pointer, s Status) Status         { return b.end(h, s) }

// Open loads the system libpam and libc with eager, local symbol resolution.
// It performs no PAM transaction or authentication. Library operations must be
// serialized by the caller; Close is rejected while transactions are active.
func Open() (*Library, error) {
	pamHandle, err := purego.Dlopen("libpam.so.0", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("pam: load libpam: %w", err)
	}
	libcHandle, err := purego.Dlopen("libc.so.6", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("pam: load libc: %w", errorsWithClose(err, pamHandle))
	}
	functions := &boundFunctions{}
	memory := &nativeAllocator{}
	bindings := []struct {
		handle uintptr
		name   string
		target any
	}{
		{pamHandle, "pam_start", &functions.start},
		{pamHandle, "pam_authenticate", &functions.authenticate},
		{pamHandle, "pam_acct_mgmt", &functions.acctMgmt},
		{pamHandle, "pam_end", &functions.end},
		{libcHandle, "malloc", &memory.malloc},
		{libcHandle, "free", &memory.freeFn},
	}
	for _, binding := range bindings {
		if err := register(binding.target, binding.handle, binding.name); err != nil {
			return nil, errorsWithClose(errorsWithClose(err, libcHandle), pamHandle)
		}
	}
	return &Library{calls: functions, memory: memory, pamHandle: pamHandle, libcHandle: libcHandle}, nil
}

// RegisterLibFunc panics on lookup/registration failure; turn that boundary into
// an Open error so a partially bound library is never exposed.
func register(target any, handle uintptr, name string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("pam: bind %s: %v", name, recovered)
		}
	}()
	purego.RegisterLibFunc(target, handle, name)
	return nil
}
