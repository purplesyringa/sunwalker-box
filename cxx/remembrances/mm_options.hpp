#include "../libc.hpp"
#include <linux/prctl.h>

namespace mm_options {

using State = prctl_mm_map;

Result<void> load(const State &state) {
    libc::prctl(PR_SET_MM, PR_SET_MM_MAP, reinterpret_cast<unsigned long>(&state), sizeof(state), 0)
        .TRY();
    return {};
}

} // namespace mm_options
