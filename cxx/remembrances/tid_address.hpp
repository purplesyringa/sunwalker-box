#include "../libc.hpp"
#include <linux/prctl.h>

namespace tid_address {

using State = size_t;

Result<void> save(State &state) {
    libc::prctl(PR_GET_TID_ADDRESS, reinterpret_cast<unsigned long>(&state), 0, 0, 0).TRY();
    return {};
}

} // namespace tid_address
