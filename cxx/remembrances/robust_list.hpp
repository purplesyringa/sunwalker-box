#include "../libc.hpp"
#include <linux/futex.h>

namespace robust_futexes {

struct State {
    robust_list_head *head;
    size_t len;
};

Result<void> save(State &state) {
    libc::get_robust_list(0, &state.head, &state.len).CONTEXT("Failed to get robust list").TRY();
    return {};
}

Result<void> load(const State &state) {
    libc::set_robust_list(state.head, state.len).CONTEXT("Failed to set robust list").TRY();
    return {};
}

} // namespace robust_futexes
