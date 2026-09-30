//go:build linux && (amd64 || arm64)

package pam

import (
	"errors"
	"fmt"
	"testing"
	"unsafe"

	"github.com/bnema/purego"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Real libc allocations plus a generated PAM seam; no real PAM transaction.
func testLibrary(t *testing.T) (*Library, *mocklibraryFunctions, unsafe.Pointer) {
	t.Helper()
	l, err := Open()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, l.Close()) })
	handle, err := l.memory.alloc(8)
	require.NoError(t, err)
	t.Cleanup(func() { l.memory.free(handle) })
	calls := newMocklibraryFunctions(t)
	l.calls = calls
	return l, calls, handle
}

func expectStart(t *testing.T, calls *mocklibraryFunctions, handle unsafe.Pointer, status Status) {
	t.Helper()
	calls.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(service, user, conv, output unsafe.Pointer) Status {
			require.Equal(t, []byte("unit-service\x00"), unsafe.Slice((*byte)(service), 13))
			require.Equal(t, []byte("unit-user\x00"), unsafe.Slice((*byte)(user), 10))
			require.Equal(t, uintptr(1), (*nativeConversation)(conv).Function)
			require.Nil(t, (*nativeConversation)(conv).Data)
			require.Nil(t, *(*unsafe.Pointer)(output))
			*(*unsafe.Pointer)(output) = handle
			return status
		}).Once()
}

func TestLoadSymbolsAndNativeMemory(t *testing.T) {
	l, err := Open()
	require.NoError(t, err)
	defer func() { require.NoError(t, l.Close()) }()
	for _, name := range []string{"pam_start", "pam_authenticate", "pam_acct_mgmt", "pam_end"} {
		address, err := purego.Dlsym(l.pamHandle, name)
		require.NoError(t, err)
		require.NotZero(t, address)
	}
	var missing func()
	require.Error(t, register(&missing, l.pamHandle, "purego_pam_nonexistent_symbol"))
	p, err := l.memory.alloc(32)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), unsafe.Slice((*byte)(p), 32))
	l.memory.free(p)
	p, err = nativeCString(l.memory, "synthetic")
	require.NoError(t, err)
	require.Equal(t, []byte("synthetic\x00"), unsafe.Slice((*byte)(p), 10))
	l.memory.free(p)
	_, err = nativeCString(l.memory, "bad\x00text")
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestNativeLayouts(t *testing.T) {
	require.Equal(t, uintptr(4), unsafe.Sizeof(Status(0)))
	require.Equal(t, uintptr(4), unsafe.Sizeof(Flags(0)))
	require.Equal(t, uintptr(8), unsafe.Sizeof(uintptr(0)))
	require.Equal(t, uintptr(16), unsafe.Sizeof(nativeMessage{}))
	require.Equal(t, uintptr(16), unsafe.Sizeof(nativeResponse{}))
	require.Equal(t, uintptr(16), unsafe.Sizeof(nativeConversation{}))
	require.Equal(t, uintptr(8), unsafe.Offsetof(nativeMessage{}.Text))
	require.Equal(t, uintptr(8), unsafe.Offsetof(nativeResponse{}.ReturnCode))
	require.Equal(t, uintptr(8), unsafe.Offsetof(nativeConversation{}.Data))
	require.Equal(t, uintptr(8), unsafe.Alignof(nativeMessage{}))
	require.Equal(t, uintptr(8), unsafe.Alignof(nativeResponse{}))
	require.Equal(t, uintptr(8), unsafe.Alignof(nativeConversation{}))
}

func TestTransactionLifecycle(t *testing.T) {
	l, calls, handle := testLibrary(t)
	expectStart(t, calls, handle, Success)
	tx, err := l.Start("unit-service", "unit-user", NativeConversation{Function: 1})
	require.NoError(t, err)
	require.ErrorIs(t, l.Close(), ErrBusy)
	calls.EXPECT().Authenticate(handle, DisallowNullAuthtok).Return(Success).Once()
	require.NoError(t, tx.Authenticate(DisallowNullAuthtok))
	calls.EXPECT().AcctMgmt(handle, Flags(0)).Return(Success).Once()
	require.NoError(t, tx.AcctMgmt(0))
	calls.EXPECT().End(handle, Success).RunAndReturn(func(_ unsafe.Pointer, _ Status) Status {
		// Native arguments are still alive while pam_end executes.
		require.Len(t, tx.storage, 4)
		require.Equal(t, []byte("unit-service\x00"), unsafe.Slice((*byte)(tx.storage[0]), 13))
		return Success
	}).Once()
	require.NoError(t, tx.End())
	require.Empty(t, tx.storage)
	require.Zero(t, l.active)
	require.ErrorIs(t, tx.End(), ErrClosed)
	require.ErrorIs(t, tx.Authenticate(0), ErrClosed)
	require.ErrorIs(t, tx.AcctMgmt(0), ErrClosed)
}

func TestEveryNonSuccessFailsClosed(t *testing.T) {
	for status := Status(1); status <= Incomplete+1; status++ {
		for _, operation := range []string{"authenticate", "acct_mgmt"} {
			t.Run(fmt.Sprintf("%s/%d", operation, status), func(t *testing.T) {
				l, calls, handle := testLibrary(t)
				expectStart(t, calls, handle, Success)
				tx, err := l.Start("unit-service", "unit-user", NativeConversation{Function: 1})
				require.NoError(t, err)
				if operation == "authenticate" {
					calls.EXPECT().Authenticate(handle, Flags(0)).Return(status).Once()
					err = tx.Authenticate(0)
				} else {
					calls.EXPECT().AcctMgmt(handle, Flags(0)).Return(status).Once()
					err = tx.AcctMgmt(0)
				}
				var nativeErr *Error
				require.ErrorAs(t, err, &nativeErr)
				require.Equal(t, status, nativeErr.Status)
				require.Equal(t, operation, nativeErr.Operation)
				calls.EXPECT().End(handle, status).Return(Success).Once()
				require.NoError(t, tx.End())
			})
		}
	}
}

func TestFailedStartAndEnd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status Status
		output bool
	}{
		{"failure-with-undefined-output", ServiceErr, true},
		{"failure-without-handle", BufErr, false},
		{"success-without-handle", Success, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, calls, handle := testLibrary(t)
			var output unsafe.Pointer
			if tc.output {
				// Output is undefined on failure: no End expectation means
				// attempting native cleanup with this value fails the test.
				output = handle
			}
			expectStart(t, calls, output, tc.status)
			tx, err := l.Start("unit-service", "unit-user", NativeConversation{Function: 1})
			require.Error(t, err)
			require.Nil(t, tx)
			require.Zero(t, l.active)
			if tc.output {
				var nativeErr *Error
				require.True(t, errors.As(err, &nativeErr))
				require.Equal(t, tc.status, nativeErr.Status)
			}
		})
	}
	t.Run("end-error-consumes-handle", func(t *testing.T) {
		l, calls, handle := testLibrary(t)
		expectStart(t, calls, handle, Success)
		tx, err := l.Start("unit-service", "unit-user", NativeConversation{Function: 1})
		require.NoError(t, err)
		calls.EXPECT().End(handle, Success).Return(SystemErr).Once()
		require.Error(t, tx.End())
		require.Empty(t, tx.storage)
		require.Zero(t, l.active)
		require.ErrorIs(t, tx.End(), ErrClosed)
	})
}

func TestArgumentAndClosedValidation(t *testing.T) {
	l, calls, handle := testLibrary(t)
	for _, tc := range []struct {
		service, user string
		conv          NativeConversation
	}{
		{"", "user", NativeConversation{Function: 1}},
		{"bad\x00service", "user", NativeConversation{Function: 1}},
		{"service", "bad\x00user", NativeConversation{Function: 1}},
		{"service", "user", NativeConversation{}},
	} {
		_, err := l.Start(tc.service, tc.user, tc.conv)
		require.ErrorIs(t, err, ErrInvalidArgument)
	}
	expectStart(t, calls, handle, Success)
	tx, err := l.Start("unit-service", "unit-user", NativeConversation{Function: 1})
	require.NoError(t, err)
	require.ErrorIs(t, tx.Authenticate(Flags(0x4000)), ErrInvalidArgument)
	require.ErrorIs(t, tx.AcctMgmt(Flags(-1)), ErrInvalidArgument)
	calls.EXPECT().End(handle, SystemErr).Return(Success).Once()
	require.NoError(t, tx.End())
	var zero Library
	_, err = zero.Start("service", "user", NativeConversation{Function: 1})
	require.ErrorIs(t, err, ErrClosed)
	require.ErrorIs(t, zero.Close(), ErrClosed)
	var absent *Transaction
	require.ErrorIs(t, absent.End(), ErrClosed)
}

func TestEmptyUserAndClosedLibrary(t *testing.T) {
	l, calls, handle := testLibrary(t)
	calls.EXPECT().Start(mock.Anything, unsafe.Pointer(nil), mock.Anything, mock.Anything).
		RunAndReturn(func(_, _, _, output unsafe.Pointer) Status { *(*unsafe.Pointer)(output) = handle; return Success }).Once()
	tx, err := l.Start("unit-service", "", NativeConversation{Function: 1})
	require.NoError(t, err)
	calls.EXPECT().End(handle, Success).Return(Success).Once()
	require.NoError(t, tx.End())
	// Close is checked separately so fixture cleanup still frees through libc.
	other, err := Open()
	require.NoError(t, err)
	require.NoError(t, other.Close())
	require.ErrorIs(t, other.Close(), ErrClosed)
	_, err = other.Start("service", "user", NativeConversation{Function: 1})
	require.ErrorIs(t, err, ErrClosed)
}
