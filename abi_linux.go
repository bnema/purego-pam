//go:build linux && (amd64 || arm64)

package pam

import "unsafe"

// Status is a Linux-PAM C int. Only Success indicates success.
type Status int32

// Linux-PAM statuses from security/_pam_types.h.
const (
	Success Status = iota
	OpenErr
	SymbolErr
	ServiceErr
	SystemErr
	BufErr
	PermDenied
	AuthErr
	CredInsufficient
	AuthinfoUnavail
	UserUnknown
	Maxtries
	NewAuthtokReqd
	AcctExpired
	SessionErr
	CredUnavail
	CredExpired
	CredErr
	NoModuleData
	ConvErr
	AuthtokErr
	AuthtokRecoveryErr
	AuthtokLockBusy
	AuthtokDisableAging
	TryAgain
	Ignore
	Abort
	AuthtokExpired
	ModuleUnknown
	BadItem
	ConvAgain
	Incomplete
)

// Flags is a Linux-PAM C int.
type Flags int32

const (
	Silent              Flags = 0x8000
	DisallowNullAuthtok Flags = 0x0001
	PromptEchoOff       int32 = 1
	PromptEchoOn        int32 = 2
	ErrorMsg            int32 = 3
	TextInfo            int32 = 4
	MaxNumMsg                 = 32
	MaxMsgSize                = 512
	MaxRespSize               = 512
)

// NativeConversation describes a caller-owned C conversation function and native
// application data. Function must implement:
// int conv(int, const struct pam_message **, struct pam_response **, void *).
// Data must be nil or libc-owned memory, NEVER a Go pointer. Function and Data
// must remain valid through End, including pam_end's cleanup callbacks.
// This low-level contract is unsafe by design; use StartConversation for the
// managed bridge instead.
type NativeConversation struct {
	Function uintptr
	Data     unsafe.Pointer
}

// Native Linux LP64 layouts; C int is 32 bits and pointers are 64 bits.
type nativeMessage struct {
	Style int32
	_     [4]byte
	Text  unsafe.Pointer
}

type nativeResponse struct {
	Text       unsafe.Pointer
	ReturnCode int32
	_          [4]byte
}

type nativeConversation struct {
	Function uintptr
	Data     unsafe.Pointer
}

// nativeCookieConversation has the same C layout, but treats appdata as an
// opaque integer value, never as an address or a Go unsafe.Pointer.
type nativeCookieConversation struct {
	Function uintptr
	Cookie   uintptr
}

// Both supported ABIs require these sizes, offsets and alignments. A mismatch
// fails compilation, including on the arm64 cross-build without a native host.
var (
	_ [16 - unsafe.Sizeof(nativeCookieConversation{})]byte
	_ [unsafe.Sizeof(nativeCookieConversation{}) - 16]byte
	_ [8 - unsafe.Offsetof(nativeCookieConversation{}.Cookie)]byte
	_ [unsafe.Offsetof(nativeCookieConversation{}.Cookie) - 8]byte
	_ [16 - unsafe.Sizeof(nativeMessage{})]byte
	_ [unsafe.Sizeof(nativeMessage{}) - 16]byte
	_ [16 - unsafe.Sizeof(nativeResponse{})]byte
	_ [unsafe.Sizeof(nativeResponse{}) - 16]byte
	_ [16 - unsafe.Sizeof(nativeConversation{})]byte
	_ [unsafe.Sizeof(nativeConversation{}) - 16]byte
	_ [8 - unsafe.Offsetof(nativeMessage{}.Text)]byte
	_ [unsafe.Offsetof(nativeMessage{}.Text) - 8]byte
	_ [8 - unsafe.Offsetof(nativeResponse{}.ReturnCode)]byte
	_ [unsafe.Offsetof(nativeResponse{}.ReturnCode) - 8]byte
	_ [8 - unsafe.Offsetof(nativeConversation{}.Data)]byte
	_ [unsafe.Offsetof(nativeConversation{}.Data) - 8]byte
	_ [8 - unsafe.Alignof(nativeMessage{})]byte
	_ [unsafe.Alignof(nativeMessage{}) - 8]byte
	_ [8 - unsafe.Alignof(nativeResponse{})]byte
	_ [unsafe.Alignof(nativeResponse{}) - 8]byte
	_ [8 - unsafe.Alignof(nativeConversation{})]byte
	_ [unsafe.Alignof(nativeConversation{}) - 8]byte
)
