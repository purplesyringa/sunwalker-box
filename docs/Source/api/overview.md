User-level API
==============

The reference library implementation in Python is documented elsewhere (where exactly?). This is the JSON API reference.

The communication with the box is done via stdio based on request-response model, where both request and responses are single lines with JSON objects.

Say, you want to request `hello` with two arguments `world` and `everyone` represented as an array. The example communication will look like this:

```json
{"command": "hello", "payload": ["world", "everyone"]}
{"status": "Success", "data": ["Hello, world!", "Hello, everyone!"]}
{"command": "hello", "payload": 1984}
{"status": "Error", "error": "Type mismatch: expected array, got integer"}
{"command": "hello"}
{"status": "Error", "error": "This command requires an argument"}
```

Due to some limitations, you probably wouldn't get a meaningful error message on malformed input. Please don't reinvent a wheel and use an existing library for JSON serialization and deserialization for your language. This also makes writing commands by hand more error-prone, so you may wish to create more friendly wrappers around this API.


Filesystem manipulations
------------------------

The sandbox manages a scratch filesystem somewhere in the RAM, which has a user-writable `/space` directory to put user files to.

See [extpath](extpath.html) and [bind](bind.html).

### **FIXME: Do not hardcode UIDs and GIDs.**

Sandbox user (and group) ids, as seen from external world are the following:
- 1, root
- 2, user

Please don't use any ids other than these for file permissions. Other ids may _or may not_ map into `nobody`. Who knows, this is an implementation detail!


Persistence and leftovers
-------------------------

All modifications to the filesystem are temporary and are not propagated to the underlying chroot. Note that read-write binds to the external filesystem _do_ propagate changes, and the changes are visible to the subsequent runs even after reset, given that you rebind the directory -- which is done, e.g. after resetting to a committed state.

See [reset](reset.html) and [commit](commit.html).
