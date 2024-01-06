#include "../libc.hpp"
#include <linux/prctl.h>

namespace thp_options {

using State = long;

static Result<void> save(State &state) {
    state = libc::prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0).TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::prctl(PR_SET_THP_DISABLE, state, 0, 0, 0).TRY();
    return {};
}

} // namespace thp_options
