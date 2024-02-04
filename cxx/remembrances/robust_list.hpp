#include "../libc.hpp"
#include "../result.hpp"

namespace robust_list {

struct State {
    void *head;
    long len;
};

Result<void> save(State &state) {
    libc::get_robust_list(0, &state.head, &state.len).CONTEXT("Failed to get robust list").TRY();
    return {};
}

Result<void> load(const State &state) {
    libc::set_robust_list(state.head, state.len).CONTEXT("Failed to set robust list").TRY();
    return {};
}

} // namespace robust_list
