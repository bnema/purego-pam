//go:build linux && (amd64 || arm64)

package pam

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestManagedStartFailureRetiresCookie(t *testing.T) {
	l, calls, _ := testLibrary(t)
	handler := NewMockConversation(t)
	var cookie uintptr
	calls.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_, _, conv, _ unsafe.Pointer) Status {
		cookie = (*nativeCookieConversation)(conv).Cookie
		return ServiceErr
	}).Once()
	tx, err := l.StartConversation("unit-service", "unit-user", handler)
	require.Error(t, err)
	require.Nil(t, tx)
	require.Nil(t, acquireConversation(cookie))
	require.Zero(t, l.active)
	_, err = l.StartConversation("unit-service", "unit-user", nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = l.StartConversation("", "unit-user", handler)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestNativeEndCanInvokeManagedConversation(t *testing.T) {
	l, calls, handle := testLibrary(t)
	handler := NewMockConversation(t)
	messages, output := nativeMessages(t, l.memory, TextInfo)
	var cookie uintptr
	calls.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_, _, c, out unsafe.Pointer) Status {
		cookie = (*nativeCookieConversation)(c).Cookie
		*(*unsafe.Pointer)(out) = handle
		return Success
	}).Once()
	tx, err := l.StartConversation("unit-service", "", handler)
	require.NoError(t, err)
	handler.EXPECT().Respond(mock.Anything, mock.Anything).Return(0, nil).Once()
	calls.EXPECT().End(handle, Success).RunAndReturn(func(_ unsafe.Pointer, _ Status) Status {
		require.Equal(t, Success, invokeConversation(t, cookie, 1, messages, output))
		l.memory.free(*(*unsafe.Pointer)(output))
		return SystemErr
	}).Once()
	require.Error(t, tx.End())
	require.Nil(t, acquireConversation(cookie))
	require.Empty(t, tx.storage)
	require.Zero(t, l.active)
}

func TestConcurrentEntriesAreSerializedAndRetirementWaits(t *testing.T) {
	l, _, _ := testLibrary(t)
	handler := NewMockConversation(t)
	s := callbackState(t, handler, l.memory)
	messages, output1 := nativeMessages(t, l.memory, TextInfo)
	_, output2 := nativeMessages(t, l.memory, TextInfo)
	entered, release := make(chan struct{}), make(chan struct{})
	second := make(chan struct{}, 1)
	handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(_ Message, _ []byte) (int, error) {
		close(entered)
		<-release
		return 0, nil
	}).Once()
	handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(_ Message, _ []byte) (int, error) {
		second <- struct{}{}
		return 0, nil
	}).Once()
	done1, done2 := make(chan Status, 1), make(chan Status, 1)
	go func() { done1 <- invokeConversation(t, s.token, 1, messages, output1) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first callback not entered")
	}
	// Admit a second entry explicitly; it holds a registry reference until its
	// callback finishes, so retirement must wait even if it closes admission.
	admitted := acquireConversation(s.token)
	require.NotNil(t, admitted)
	go func() {
		done2 <- invokeConversation(t, s.token, 1, messages, output2)
		admitted.leave()
	}()
	select {
	case <-second:
		t.Fatal("handler reentered while first was active")
	default:
	}
	// Do not retire until both actual callbacks finished: native calls above
	// exercise serialization, while explicit admitted reference tests the wait.
	close(release)
	select {
	case status := <-done1:
		require.Equal(t, Success, status)
	case <-time.After(3 * time.Second):
		t.Fatal("first callback blocked")
	}
	select {
	case status := <-done2:
		require.Equal(t, Success, status)
	case <-time.After(3 * time.Second):
		t.Fatal("second callback blocked")
	}
	for _, output := range []unsafe.Pointer{output1, output2} {
		l.memory.free(*(*unsafe.Pointer)(output))
	}
	held := acquireConversation(s.token)
	require.NotNil(t, held)
	retired := make(chan struct{})
	go func() { s.retire(); close(retired) }()
	select {
	case <-retired:
		t.Fatal("retirement ignored admitted reference")
	default:
	}
	held.leave()
	select {
	case <-retired:
	case <-time.After(3 * time.Second):
		t.Fatal("retirement did not finish")
	}
	require.Nil(t, acquireConversation(s.token))
}

func TestMaximumAnswerAndMessageCount(t *testing.T) {
	l, _, _ := testLibrary(t)
	handler := NewMockConversation(t)
	s := callbackState(t, handler, l.memory)
	styles := make([]int32, MaxNumMsg)
	for i := range styles {
		styles[i] = PromptEchoOff
	}
	messages, output := nativeMessages(t, l.memory, styles...)
	handler.EXPECT().Respond(mock.Anything, mock.Anything).RunAndReturn(func(_ Message, answer []byte) (int, error) {
		for i := range answer {
			answer[i] = 'x'
		}
		return MaxRespSize, nil
	}).Times(MaxNumMsg)
	require.Equal(t, Success, invokeConversation(t, s.token, MaxNumMsg, messages, output))
	p := *(*unsafe.Pointer)(output)
	for _, response := range unsafe.Slice((*nativeResponse)(p), MaxNumMsg) {
		bytes := unsafe.Slice((*byte)(response.Text), MaxRespSize+1)
		require.Equal(t, byte('x'), bytes[MaxRespSize-1])
		require.Zero(t, bytes[MaxRespSize])
		l.memory.free(response.Text)
	}
	l.memory.free(p)
}
