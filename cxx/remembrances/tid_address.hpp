#include "../libc.hpp"
#include "../result.hpp"
#include <sys/prctl.h>

namespace tid_address {

using State = size_t;

Result<void> save(State &state) {
    libc::prctl(PR_GET_TID_ADDRESS, &state).TRY();
    return {};
}

} // namespace tid_address
