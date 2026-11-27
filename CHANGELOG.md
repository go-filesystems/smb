# Changelog

## v0.20.1

- Fix a data race in the SMB 3 encrypt path: bump go-filesystems/go-smb2 to
  v0.1.1, where a send abandoned by its context no longer lets the next send
  re-encode over a packet the writer goroutine is still writing (reported by
  `go test -race` in `session.encrypt`). The CI `race detector` job runs
  `go test -race ./...`, which includes the encryption tests.
