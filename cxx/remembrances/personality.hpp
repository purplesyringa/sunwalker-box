#include "../libc.hpp"

// Holy echopraxia

namespace personality {

using State = long;

static Result<void> save(State &state) {
    state = libc::personality(0xffffffff).TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::personality(state).TRY();
    return {};
}

} // namespace personality
