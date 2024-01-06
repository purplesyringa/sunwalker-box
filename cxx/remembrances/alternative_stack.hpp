#include "../libc.hpp"
namespace alternative_stack {

using State = stack_t;

static Result<void> save(State &state) {
    libc::sigaltstack(nullptr, &state).TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::sigaltstack(&state, nullptr).TRY();
    return {};
}

} // namespace alternative_stack
