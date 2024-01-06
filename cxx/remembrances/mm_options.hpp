#include <sys/prctl.h>
#include "../libc.hpp"
#include "../result.hpp"

namespace mm_options {

using State = prctl_mm_map;

static Result<void> load(const State& state) {
    libc::prctl(PR_SET_MM, PR_SET_MM_MAP, &state, sizeof(state), 0).TRY();
    return {};
}

}
