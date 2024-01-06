#include "../libc.hpp"

namespace program_break {

using State = size_t;

static Result<void> save(State &state) {
    state = libc::brk(0).TRY();
    return {};
}

} // namespace program_break
