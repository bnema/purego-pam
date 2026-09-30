# Repository rules

- Go 1.27; builds and tests use CGO_ENABLED=0. Race tests use CGO_ENABLED=1.
- Mocks are Mockery v3 generated only; no handwritten fakes or doubles.
- Native memory: PAM answers are allocated with libc malloc and wiped before free. Prompt and answer buffers are wiped on every path.
- Commits are signed and follow Conventional Commits.
- Run `make check` and `make race` before merge.
