#include "../libc.hpp"
#include <linux/prctl.h>

namespace tid_address {

using State = size_t;

static Result<void> save(State &state) {
    libc::prctl(PR_GET_TID_ADDRESS, reinterpret_cast<unsigned long>(&state), 0, 0, 0).TRY();
    return {};
}

static Result<void> load(const State &state) {
    libc::set_tid_address(reinterpret_cast<int *>(state)).TRY();
    return {};
}

} // namespace tid_address
