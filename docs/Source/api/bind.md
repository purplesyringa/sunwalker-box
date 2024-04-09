### `bind {internal, external, ro}` -- create a file or directory mirror

- `external` path -- that is the path relative to the external root (what about supplied root?)
- `internal` path -- that is relative to the sandboxed root
- `ro` flag -- tells the box to make the bind read-only if set to true

Returns nothing.

The file/directory at the internal path must already exist inside the sandbox; if they don't, create them before. (What about mode bits?)
