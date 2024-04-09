### `reset` -- reset sandbox to the initial state

Resets everything to the initial state: filesystem, PIDs, temporary files, network data, etc.

The filesystem is reset only after an explicit request. Make sure to request filesystem reset if you don't want to leave traces of prior launch in the box filesystem.

The filesystem is reset to committed state if it exists, or to the initial state.
