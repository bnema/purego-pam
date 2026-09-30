# purego-pam

Linux-PAM binding for **Go 1.27**, normally built with
**CGO_ENABLED=0**, using `github.com/bnema/purego`. Supported ABI targets:
Linux amd64 and arm64 (LP64, 32-bit C `int`). This is not an authentication
product.

## API

- `Open() (*Library, error)` loads system `libpam.so.0` and `libc.so.6` with
  eager, local symbol resolution. Binding failure returns an error.
- `Library.Start(service, user, NativeConversation)` requires an explicit
  nonempty service and a native conversation function. Empty user becomes
  NULL; embedded NULs are rejected.
- `Library.StartConversation(service, user, Conversation)` adds the managed Go
  conversation bridge with library-owned answer buffers.
- `Transaction.Authenticate(flags)` and `AcctMgmt(flags)` return nil only for
  PAM_SUCCESS. Every other status produces a typed `*Error`. Supported flags
  are SILENT and DISALLOW_NULL_AUTHTOK; other bits are rejected.
- `Transaction.End()` passes the last operation status, consumes the
  transaction even on error, and releases native storage after `pam_end`
  returns. Reuse is rejected.
- `Library.Close()` rejects active transactions before unloading symbols.

Neither Library nor Transaction may be copied. Their zero values are closed.
All operations on a Library and its Transactions require serialized caller
ownership. Native calls are synchronous and may block; there is no timeout,
cancellation, or thread-affinity guarantee.

Authentication success alone is not account authorization. Callers must check
both Authenticate and AcctMgmt; End is cleanup, not permission to grant access.
The library does not install or validate PAM service policy. System fallback
configuration may apply when the named service is absent.

## Native memory boundary

Start copies service/user strings into libc-owned memory and allocates the
conversation structure and handle output slot there. Storage remains valid
through End. On failed Start, the undefined output handle is never read or
passed to `pam_end`. Successful Start with a NULL handle fails closed.

`NativeConversation` is a **trusted unsafe boundary**, not a safe Go callback
API. `Function` must be a valid C-ABI conversation function address. `Data`
must be NULL or caller-owned native memory, never a Go pointer. The caller
must keep both valid until End returns; the type system cannot validate these
addresses. This external API is distinct from the managed bridge below.

## Managed conversation bridge

`Conversation.Respond(Message, answer []byte) (length int, err error)` receives
copied message bytes and a zeroed 512-byte answer buffer. Write a non-NUL answer
and return its byte length; informational messages require length zero. Do not
retain buffers, log their contents, call transaction/library methods from the
handler, or recursively invoke its conversation. Handler calls are serialized
per conversation, including concurrent native entries. A handler must return;
End can wait indefinitely for a blocked handler.

The bridge handles 1..32 Linux-PAM messages, represented as an array of message
pointers. It accepts ECHO_OFF, ECHO_ON, ERROR_MSG and TEXT_INFO only. Message text
must be NUL-terminated within 512 bytes; answers may contain at most 512 bytes.
NULL and alignment checks do not make arbitrary native addresses safe: PAM
modules must supply readable message memory and writable output slots.

One shared C-ABI callback lives for the process lifetime and is never
unreferenced. Application data contains a nonreused numeric opaque cookie,
**not a memory address**; neither PAM nor the bridge may dereference it. Unknown
or retired cookies return CONV_ERR without touching message/output memory.
Registry admission remains open during `pam_end`, then closes and waits for
admitted callbacks before transaction storage is freed. Native modules that
continue callbacks after `pam_end` violate the normal lifetime contract;
retired cookies reject their calls, but this does not validate their behavior.

Responses are a contiguous libc-owned array with zero return codes and
libc-owned strings for prompts. Successful return transfers ownership to the
PAM module, which must free both. Failure publishes no response array and wipes
and frees partial native answer allocations. Go prompt and answer buffers are
wiped on success, handler error, and handler panic. Errors and panic payloads
are not logged or returned. Handler-private copies and successful native
responses after ownership transfer remain outside the library's wiping control.

## Development

Production code depends on `github.com/bnema/purego` and the standard library. Tests use Mockery v3's
generated testify mocks of PAM calls, conversation handlers and native memory
through `EXPECT()` and
`RunAndReturn`, alongside real libc allocations.

```sh
make check  # vet, test, build (incl. arm64), mocks-check, staticcheck
make race                       # separate CGO1 race diagnostic
```

Make targets use offline module resolution. Go requires CGO_ENABLED=1 for
`-race`; no C helper is included. Tests require installed system libpam/libc
and resolve PAM symbols, but PAM transaction calls go only to generated
mocks. Synthetic `purego.SyscallN` calls exercise the actual callback ABI,
including failure cleanup and callback retirement. Tests use no real
authentication or credentials. Native layout sizes,
offsets, and alignment have compile-time assertions for both targets; arm64
native calls remain unverified without a matching libc/libpam sysroot.

Not included: PAM service installation, CLI,
worker process, defaults, setuid, shadow/password handling, sessions,
credential establishment, or password changes.

## License

MIT. See LICENSE.
