//go:build linux && (amd64 || arm64)

package pam

import (
	"errors"
	"strings"
	"unsafe"
)

var ErrAllocation = errors.New("pam: native allocation failed")

type nativeAllocator struct {
	malloc func(uintptr) unsafe.Pointer
	freeFn func(unsafe.Pointer)
}

// alloc returns zero-filled malloc-owned memory; free must come from the same
// libc. Returning unsafe.Pointer directly avoids uintptr-to-pointer arithmetic.
func (a *nativeAllocator) alloc(size uintptr) (unsafe.Pointer, error) {
	p := a.malloc(size)
	if p == nil {
		return nil, ErrAllocation
	}
	clear(unsafe.Slice((*byte)(p), int(size)))
	return p, nil
}

func (a *nativeAllocator) free(p unsafe.Pointer) { a.freeFn(p) }

func nativeCString(a nativeMemory, text string) (unsafe.Pointer, error) {
	if strings.ContainsRune(text, '\x00') {
		return nil, ErrInvalidArgument
	}
	p, err := a.alloc(uintptr(len(text)) + 1)
	if err != nil {
		return nil, err
	}
	copy(unsafe.Slice((*byte)(p), len(text)+1), text)
	return p, nil
}
