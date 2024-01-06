#include "../libc.hpp"

namespace umask {

using State = mode_t;

static Result<void> save(State &state) {
    state = libc::umask(0).TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::umask(state).TRY();
    return {};
}

} // namespace umask
