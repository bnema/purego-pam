//go:build linux && (amd64 || arm64)

package pam

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/bnema/purego"
)

// Message is a copied Linux-PAM message. Text may be sensitive and is wiped
// after Respond returns. Do not retain it; do not log prompts or answers.
type Message struct {
	Style int32
	Text  []byte
}

// Conversation supplies responses without retaining native or Go buffers.
// Respond receives a zeroed MaxRespSize-byte answer buffer. Write the answer
// there and return its length (0..MaxRespSize), without a NUL. For informational
// messages return zero. The library wipes Text and answer even on error/panic.
// Do not retain buffers or access them after return, or call Library/Transaction
// methods from Respond. Respond must return: no timeout cancels a native call.
// Calls for one conversation are serialized, including foreign-thread entry.
// Any private secret copies made by the handler remain its responsibility.
type Conversation interface {
	Respond(message Message, answer []byte) (int, error)
}

// nativeMemory is the allocator seam for callback failure tests.
type nativeMemory interface {
	alloc(size uintptr) (unsafe.Pointer, error)
	free(pointer unsafe.Pointer)
}

type conversationState struct {
	token   uintptr
	handler Conversation
	memory  nativeMemory
	serial  sync.Mutex
	refs    int // guarded by conversations.Mutex
}

var conversations = struct {
	sync.Mutex
	next   uintptr
	states map[uintptr]*conversationState
}{states: make(map[uintptr]*conversationState)}
var conversationChanged = sync.NewCond(&conversations.Mutex)
var sharedCallback struct {
	sync.Once
	address uintptr
	err     error
}

// The shared callback is never unreferenced: late calls can safely reject an
// unknown cookie without reading any appdata, message or output memory.
func callbackAddress() (uintptr, error) {
	sharedCallback.Do(func() {
		defer func() {
			if recover() != nil {
				sharedCallback.err = errors.New("pam: callback registration failed")
			}
		}()
		sharedCallback.address = purego.NewCallbackInts(conversationCallback)
	})
	return sharedCallback.address, sharedCallback.err
}

func registerConversation(handler Conversation, memory nativeMemory) (*conversationState, error) {
	conversations.Lock()
	defer conversations.Unlock()
	if conversations.next == ^uintptr(0) {
		return nil, errors.New("pam: conversation cookie space exhausted")
	}
	conversations.next++ // never reuse a cookie, including after failed Start
	s := &conversationState{token: conversations.next, handler: handler, memory: memory}
	conversations.states[s.token] = s
	return s, nil
}

func acquireConversation(token uintptr) *conversationState {
	conversations.Lock()
	defer conversations.Unlock()
	s := conversations.states[token]
	if s != nil {
		s.refs++
	}
	return s
}

func (s *conversationState) leave() {
	conversations.Lock()
	s.refs--
	conversationChanged.Broadcast()
	conversations.Unlock()
}

func (s *conversationState) retire() {
	conversations.Lock()
	delete(conversations.states, s.token) // close admission before waiting
	for s.refs != 0 {
		conversationChanged.Wait()
	}
	conversations.Unlock()
}

// StartConversation adds the managed Go bridge; the external NativeConversation
// API is unchanged. appdata is a numeric opaque void* cookie, NOT a pointer to
// memory, and neither PAM nor the bridge may dereference it.
func (l *Library) StartConversation(service, user string, handler Conversation) (*Transaction, error) {
	if l == nil || l.closed || l.calls == nil || l.memory == nil {
		return nil, ErrClosed
	}
	if handler == nil {
		return nil, ErrInvalidArgument
	}
	address, err := callbackAddress()
	if err != nil {
		return nil, err
	}
	s, err := registerConversation(handler, l.memory)
	if err != nil {
		return nil, err
	}
	t, err := l.start(service, user, NativeConversation{Function: address}, s)
	if err != nil {
		s.retire()
	}
	return t, err
}

// Raw integer-class entry keeps all native address bits out of Go pointer
// values until cookie admission. C int count uses only the low 32 bits.
func conversationCallback(args *purego.CallbackArgs) (result uintptr) {
	result = uintptr(ConvErr)
	defer func() {
		if recover() != nil {
			result = uintptr(ConvErr)
		}
	}()
	count, cookie := int32(args.Int(0)), args.Int(3)
	s := acquireConversation(cookie)
	if s == nil {
		return result
	}
	defer s.leave()
	messages, output := args.Int(1), args.Int(2)
	if count < 1 || count > MaxNumMsg || messages == 0 || output == 0 ||
		messages%unsafe.Alignof(uintptr(0)) != 0 || output%unsafe.Alignof(uintptr(0)) != 0 {
		return result
	}
	return uintptr(uint32(s.respondNative(count, admittedNativeAddress(messages), admittedNativeAddress(output))))
}

// admittedNativeAddress reinterprets native address bits only after admission
// and basic validation. This is not an address-validity guarantee; the admitted
// native caller must supply readable/writable memory throughout the call.
func admittedNativeAddress(bits uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&bits))
}

func (s *conversationState) respondNative(count int32, messages, output unsafe.Pointer) (status Status) {
	status = ConvErr
	s.serial.Lock()
	defer s.serial.Unlock()
	var responses unsafe.Pointer
	var lengths []int
	transferred := false
	defer func() {
		if recover() != nil {
			status = ConvErr
		} // never expose panic payload
		if responses != nil && !transferred {
			s.cleanupResponses(responses, lengths)
		}
	}()
	if count < 1 || count > MaxNumMsg || messages == nil || output == nil {
		return status
	}
	// Trusted native caller must supply readable arrays and writable output;
	// NULL checks and bounded reads cannot validate arbitrary native addresses.
	if uintptr(messages)%unsafe.Alignof(uintptr(0)) != 0 || uintptr(output)%unsafe.Alignof(uintptr(0)) != 0 {
		return status
	}
	*(*unsafe.Pointer)(output) = nil
	lengths = make([]int, int(count))
	var err error
	responses, err = s.memory.alloc(uintptr(count) * unsafe.Sizeof(nativeResponse{}))
	if err != nil {
		return BufErr
	}
	array := unsafe.Slice((*nativeResponse)(responses), int(count))
	pointers := unsafe.Slice((*unsafe.Pointer)(messages), int(count))
	for i, pointer := range pointers {
		if pointer == nil || uintptr(pointer)%unsafe.Alignof(nativeMessage{}) != 0 {
			return ConvErr
		}
		message := *(*nativeMessage)(pointer)
		if message.Style != PromptEchoOff && message.Style != PromptEchoOn && message.Style != ErrorMsg && message.Style != TextInfo {
			return ConvErr
		}
		text, ok := copyMessage(message.Text)
		if !ok {
			return ConvErr
		}
		answer, n, err := respond(s.handler, Message{Style: message.Style, Text: text})
		if err != nil {
			return ConvErr
		}
		// respond's caller owns wiping the returned answer after native copy.
		result := func() Status {
			defer clear(answer)
			if message.Style == ErrorMsg || message.Style == TextInfo {
				if n != 0 {
					return ConvErr
				}
				return Success
			}
			p, err := s.memory.alloc(uintptr(n + 1))
			if err != nil {
				return BufErr
			}
			copy(unsafe.Slice((*byte)(p), n+1), answer[:n])
			array[i].Text = p
			lengths[i] = n
			return Success
		}()
		if result != Success {
			return result
		}
	}
	*(*unsafe.Pointer)(output) = responses
	transferred = true // PAM/module now owns array and response strings via free
	return Success
}

// Schedule every free before executing any, so a panicking allocator seam's
// free cannot prevent release of the other known native allocations. The raw
// entry catches cleanup panics without exposing their payload.
func (s *conversationState) cleanupResponses(responses unsafe.Pointer, lengths []int) {
	defer s.memory.free(responses)
	for i, response := range unsafe.Slice((*nativeResponse)(responses), len(lengths)) {
		if response.Text != nil {
			defer func(pointer unsafe.Pointer, size int) {
				defer s.memory.free(pointer)
				clear(unsafe.Slice((*byte)(pointer), size))
			}(response.Text, lengths[i]+1)
		}
	}
}

func copyMessage(pointer unsafe.Pointer) ([]byte, bool) {
	if pointer == nil {
		return nil, false
	}
	// Read one byte at a time; do not form/read a whole maximum-length slice
	// beyond a short string. Caller still must provide readable native memory.
	for n := 0; n < MaxMsgSize; n++ {
		if *(*byte)(unsafe.Add(pointer, n)) == 0 {
			return append([]byte(nil), unsafe.Slice((*byte)(pointer), n)...), true
		}
	}
	return nil, false
}

func respond(handler Conversation, message Message) (answer []byte, n int, err error) {
	answer = make([]byte, MaxRespSize)
	defer clear(message.Text)
	defer func() {
		if recover() != nil {
			err = errors.New("pam: conversation handler failed")
		}
		if err != nil {
			clear(answer)
		}
	}()
	n, err = handler.Respond(message, answer)
	if err == nil {
		if n < 0 || n > len(answer) {
			err = ErrInvalidArgument
		} else {
			for _, b := range answer[:n] {
				if b == 0 {
					err = ErrInvalidArgument
					break
				}
			}
		}
	}
	return
}
