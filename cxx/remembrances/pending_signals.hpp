#include "../libc.hpp"

namespace pending_signals {

using State = uint64_t;

Result<void> save(State &state) {
    // TODO: we'd better lift this restriction somehow
    libc::rt_sigpending(&state, 8).CONTEXT("Failed to run rt_sigpending").TRY();
    ENSURE(state == 0, "sunwalker cannot suspend processes with pending signals");
    return {};
}

} // namespace pending_signals
