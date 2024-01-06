#include "../libc.hpp"

namespace signal_mask {

using State = uint64_t;

static Result<void> save(State &state) {
    libc::rt_sigprocmask(SIG_BLOCK, nullptr, &state, sizeof(state)).TRY();
    return {};
}

} // namespace signal_mask
