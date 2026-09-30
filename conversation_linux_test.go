//go:build linux && (amd64 || arm64)

package pam

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/bnema/purego"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func nativeMessages(t *testing.T, memory nativeMemory, styles ...int32) (unsafe.Pointer, unsafe.Pointer) {
	t.Helper()
	pointers, err := memory.alloc(uintptr(len(styles)) * 8)
	require.NoError(t, err)
	t.Cleanup(func() { memory.free(pointers) })
	for i, style := range styles {
		text, err := nativeCString(memory, "synthetic prompt")
		require.NoError(t, err)
		t.Cleanup(func() { memory.free(text) })
		message, err := memory.alloc(16)
		require.NoError(t, err)
		t.Cleanup(func() { memory.free(message) })
		*(*nativeMessage)(message) = nativeMessage{Style: style, Text: text}
		unsafe.Slice((*unsafe.Pointer)(pointers), len(styles))[i] = message
	}
	output, err := memory.alloc(8)
	require.NoError(t, err)
	t.Cleanup(func() { memory.free(output) })
	return pointers, output
}

func invokeConversation(t *testing.T, cookie uintptr, count int32, messages, output unsafe.Pointer) Status {
	t.Helper()
	address, err := callbackAddress()
	require.NoError(t, err)
	result, _, _ := purego.SyscallN(address, uintptr(count), uintptr(messages), uintptr(output), cookie)
	return Status(int32(result))
}

func callbackState(t *testing.T, handler Conversation, memory nativeMemory) *conversationState {
	t.Helper()
	state, err := registerConversation(handler, memory)
	require.NoError(t, err)
	t.Cleanup(state.retire)
	return state
}

func TestConversationCABIAndResponseOwnership(t *testing.T) {
	l, _, _ := testLibrary(t)
	handler := NewMockConversation(t)
	s := callbackState(t, handler, l.memory)
	messages, output := nativeMessages(t, l.memory, PromptEchoOff, PromptEchoOn, ErrorMsg, TextInfo)
	var answers, prompts [][]byte
	handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(message Message, answer []byte) (int, error) {
		require.Equal(t, "synthetic prompt", string(message.Text))
		require.Equal(t, make([]byte, MaxRespSize), answer)
		answers = append(answers, answer)
		prompts = append(prompts, message.Text)
		if message.Style == PromptEchoOff || message.Style == PromptEchoOn {
			copy(answer, "synthetic answer")
			return 16, nil
		}
		return 0, nil
	}).Times(4)
	require.Equal(t, Success, invokeConversation(t, s.token, 4, messages, output))
	for _, answer := range answers {
		require.Equal(t, make([]byte, len(answer)), answer)
	}
	for _, prompt := range prompts {
		require.Equal(t, make([]byte, len(prompt)), prompt)
	}
	responses := *(*unsafe.Pointer)(output)
	require.NotNil(t, responses)
	array := unsafe.Slice((*nativeResponse)(responses), 4)
	for i := range array {
		require.Zero(t, array[i].ReturnCode)
		if i < 2 {
			require.Equal(t, []byte("synthetic answer\x00"), unsafe.Slice((*byte)(array[i].Text), 17))
			l.memory.free(array[i].Text) // simulate PAM ownership release
		} else {
			require.Nil(t, array[i].Text)
		}
	}
	l.memory.free(responses)
}

func TestHandlerFailureAndBoundsWipeBuffers(t *testing.T) {
	for _, scenario := range []string{"error", "panic", "negative", "oversize", "embedded-nul", "info-answer"} {
		t.Run(scenario, func(t *testing.T) {
			l, _, _ := testLibrary(t)
			handler := NewMockConversation(t)
			s := callbackState(t, handler, l.memory)
			style := PromptEchoOff
			if scenario == "info-answer" {
				style = TextInfo
			}
			messages, output := nativeMessages(t, l.memory, style)
			var capturedAnswer, capturedPrompt []byte
			handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(message Message, answer []byte) (int, error) {
				capturedAnswer, capturedPrompt = answer, message.Text
				copy(answer, "synthetic")
				switch scenario {
				case "error":
					return 9, errors.New("sensitive payload must not escape")
				case "panic":
					panic("sensitive panic must not escape")
				case "negative":
					return -1, nil
				case "oversize":
					return MaxRespSize + 1, nil
				case "embedded-nul":
					return 10, nil
				default:
					return 9, nil
				}
			}).Once()
			require.Equal(t, ConvErr, invokeConversation(t, s.token, 1, messages, output))
			require.Nil(t, *(*unsafe.Pointer)(output))
			require.Equal(t, make([]byte, len(capturedAnswer)), capturedAnswer)
			require.Equal(t, make([]byte, len(capturedPrompt)), capturedPrompt)
		})
	}
}

func TestNativeInputValidation(t *testing.T) {
	for _, scenario := range []string{"zero", "too-many", "negative", "null-array", "null-output", "null-message", "null-text", "binary", "unterminated", "unaligned-array", "unaligned-output", "unaligned-message"} {
		t.Run(scenario, func(t *testing.T) {
			l, _, _ := testLibrary(t)
			handler := NewMockConversation(t) // no Respond allowed
			s := callbackState(t, handler, l.memory)
			messages, output := nativeMessages(t, l.memory, PromptEchoOff)
			message := (*nativeMessage)(*(*unsafe.Pointer)(messages))
			count := int32(1)
			switch scenario {
			case "zero":
				count = 0
			case "too-many":
				count = MaxNumMsg + 1
			case "negative":
				count = -1
			case "null-array":
				messages = nil
			case "null-output":
				output = nil
			case "null-message":
				*(*unsafe.Pointer)(messages) = nil
			case "null-text":
				message.Text = nil
			case "binary":
				message.Style = 7
			case "unterminated":
				p, err := l.memory.alloc(MaxMsgSize)
				require.NoError(t, err)
				t.Cleanup(func() { l.memory.free(p) })
				for i := range unsafe.Slice((*byte)(p), MaxMsgSize) {
					unsafe.Slice((*byte)(p), MaxMsgSize)[i] = 'x'
				}
				message.Text = p
			case "unaligned-array":
				messages = unsafe.Add(messages, 1)
			case "unaligned-output":
				output = unsafe.Add(output, 1)
			case "unaligned-message":
				*(*unsafe.Pointer)(messages) = unsafe.Add(unsafe.Pointer(message), 1)
			}
			require.Equal(t, ConvErr, invokeConversation(t, s.token, count, messages, output))
		})
	}
	t.Run("unknown-cookie-does-not-touch-pointers", func(t *testing.T) {
		l, _, _ := testLibrary(t)
		s := callbackState(t, NewMockConversation(t), l.memory)
		s.retire()
		address, err := callbackAddress()
		require.NoError(t, err)
		// Deliberately invalid addresses never converted to Go pointers.
		result, _, _ := purego.SyscallN(address, 1, 1, 1, s.token)
		require.Equal(t, ConvErr, Status(int32(result)))
	})
}

func TestAllocationFailuresCleanPartialNativeResponses(t *testing.T) {
	for failAt := 0; failAt < 3; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			l, _, _ := testLibrary(t)
			memory := newMocknativeMemory(t)
			handler := NewMockConversation(t)
			s := callbackState(t, handler, memory)
			messages, output := nativeMessages(t, l.memory, PromptEchoOff, PromptEchoOn)
			index := 0
			allocated := make(map[unsafe.Pointer]uintptr)
			memory.EXPECT().alloc(mock.Anything).RunAndReturn(func(size uintptr) (unsafe.Pointer, error) {
				current := index
				index++
				if current == failAt {
					return nil, ErrAllocation
				}
				p, err := l.memory.alloc(size)
				allocated[p] = size
				return p, err
			}).Times(failAt + 1)
			if failAt > 0 {
				memory.EXPECT().free(mock.Anything).Run(func(p unsafe.Pointer) {
					size, ok := allocated[p]
					require.True(t, ok)
					if size == 4 {
						require.Equal(t, make([]byte, 4), unsafe.Slice((*byte)(p), 4))
					}
					delete(allocated, p)
					l.memory.free(p)
				}).Times(failAt)
			}
			var answers [][]byte
			if failAt > 0 {
				handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(_ Message, answer []byte) (int, error) {
					answers = append(answers, answer)
					copy(answer, "abc")
					return 3, nil
				}).Times(failAt)
			}
			require.Equal(t, BufErr, invokeConversation(t, s.token, 2, messages, output))
			require.Nil(t, *(*unsafe.Pointer)(output))
			require.Empty(t, allocated)
			for _, answer := range answers {
				require.Equal(t, make([]byte, len(answer)), answer)
			}
		})
	}
}

func TestEndRetiresAfterNativeCleanupAndWaitsForCallbacks(t *testing.T) {
	l, calls, handle := testLibrary(t)
	handler := NewMockConversation(t)
	messages, output := nativeMessages(t, l.memory, TextInfo)
	var conv nativeCookieConversation
	calls.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_, _, c, out unsafe.Pointer) Status {
		conv = *(*nativeCookieConversation)(c)
		*(*unsafe.Pointer)(out) = handle
		return Success
	}).Once()
	tx, err := l.StartConversation("unit-service", "unit-user", handler)
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(_ Message, _ []byte) (int, error) {
		close(entered)
		<-release
		return 0, nil
	}).Once()
	callbackDone := make(chan Status, 1)
	go func() { callbackDone <- invokeConversation(t, conv.Cookie, 1, messages, output) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not enter")
	}
	cleanupReturned := make(chan struct{})
	calls.EXPECT().End(handle, Success).RunAndReturn(func(_ unsafe.Pointer, _ Status) Status {
		// Admission must still be open during pam_end cleanup.
		s := acquireConversation(conv.Cookie)
		require.NotNil(t, s)
		s.leave()
		close(cleanupReturned)
		return Success
	}).Once()
	endDone := make(chan error, 1)
	go func() { endDone <- tx.End() }()
	select {
	case <-cleanupReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("native End did not return")
	}
	select {
	case <-endDone:
		t.Fatal("End returned before callback finished")
	default:
	}
	close(release)
	select {
	case status := <-callbackDone:
		require.Equal(t, Success, status)
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not finish")
	}
	select {
	case err := <-endDone:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("End did not finish")
	}
	require.Zero(t, l.active)
	require.Empty(t, tx.storage)
	require.Equal(t, ConvErr, invokeConversation(t, conv.Cookie, 1, nil, nil))
	l.memory.free(*(*unsafe.Pointer)(output))
	address, err := callbackAddress()
	require.NoError(t, err)
	require.Equal(t, conv.Function, address)
}
