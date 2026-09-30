//go:build linux && (amd64 || arm64)

package pam

import (
	"testing"
	"unsafe"

	"github.com/bnema/purego"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRawCallbackRejectsUnknownAndRetiredArbitraryBits(t *testing.T) {
	l, _, _ := testLibrary(t)
	s := callbackState(t, NewMockConversation(t), l.memory)
	s.retire()
	address, err := callbackAddress()
	require.NoError(t, err)
	for _, cookie := range []uintptr{0, s.token, ^uintptr(0)} {
		for _, count := range []uintptr{1, 0, ^uintptr(0), uintptr(1)<<32 | 1} {
			for _, bits := range []uintptr{0, 1, 8, ^uintptr(0), uintptr(1) << 63} {
				// All values stay integers throughout unknown-cookie admission.
				// Both aligned and noncanonical addresses must be ignored.
				result, _, _ := purego.SyscallN(address, count, bits, ^bits, cookie)
				require.Equal(t, uintptr(ConvErr), result)
			}
		}
	}
}

func TestCookieExhaustionNeverWrapsOrReuses(t *testing.T) {
	l, _, _ := testLibrary(t)
	handler := NewMockConversation(t)
	conversations.Lock()
	require.Empty(t, conversations.states)
	previous := conversations.next
	conversations.next = ^uintptr(0) - 1
	conversations.Unlock()
	// Test-only counter isolation; production never resets the counter.
	t.Cleanup(func() {
		conversations.Lock()
		defer conversations.Unlock()
		require.Empty(t, conversations.states)
		conversations.next = previous
	})
	last, err := registerConversation(handler, l.memory)
	require.NoError(t, err)
	require.Equal(t, ^uintptr(0), last.token)
	last.retire()
	for range 2 {
		s, err := registerConversation(handler, l.memory)
		require.Error(t, err)
		require.Nil(t, s)
		conversations.Lock()
		require.Equal(t, ^uintptr(0), conversations.next)
		require.Empty(t, conversations.states)
		conversations.Unlock()
	}
}

func TestAllocatorPanicsStillWipeAndReleasePartialResponses(t *testing.T) {
	for _, panicFree := range []bool{false, true} {
		t.Run(map[bool]string{false: "alloc-panic", true: "alloc-and-free-panic"}[panicFree], func(t *testing.T) {
			l, _, _ := testLibrary(t)
			memory := newMocknativeMemory(t)
			handler := NewMockConversation(t)
			s := callbackState(t, handler, memory)
			messages, output := nativeMessages(t, l.memory, PromptEchoOff, PromptEchoOn)
			allocated := make(map[unsafe.Pointer]uintptr)
			index := 0
			memory.EXPECT().alloc(mock.Anything).RunAndReturn(func(size uintptr) (unsafe.Pointer, error) {
				index++
				if index == 3 {
					panic("allocator payload must not escape")
				}
				p, err := l.memory.alloc(size)
				allocated[p] = size
				return p, err
			}).Times(3)
			memory.EXPECT().free(mock.Anything).Run(func(p unsafe.Pointer) {
				size, ok := allocated[p]
				require.True(t, ok)
				if size == 4 {
					require.Equal(t, make([]byte, 4), unsafe.Slice((*byte)(p), 4))
				}
				delete(allocated, p)
				l.memory.free(p)
				if panicFree && size == 4 {
					panic("free payload must not escape")
				}
			}).Times(2)
			var answers, prompts [][]byte
			handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(message Message, answer []byte) (int, error) {
				answers = append(answers, answer)
				prompts = append(prompts, message.Text)
				copy(answer, "abc")
				return 3, nil
			}).Times(2)
			require.Equal(t, ConvErr, invokeConversation(t, s.token, 2, messages, output))
			require.Nil(t, *(*unsafe.Pointer)(output))
			require.Empty(t, allocated)
			for _, bytes := range append(answers, prompts...) {
				require.Equal(t, make([]byte, len(bytes)), bytes)
			}
			// Reference release also survives allocator and cleanup panics.
			conversations.Lock()
			require.Zero(t, s.refs)
			conversations.Unlock()
			s.retire()
		})
	}
}
