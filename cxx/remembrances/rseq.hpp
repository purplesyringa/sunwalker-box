#include "../libc.hpp"

namespace rsequence {

struct State {
    struct rseq *rseq;
    uint32_t rseq_len;
    int flags;
    uint32_t sig;
};

Result<void> load(const State &state) {
    if (state.rseq_len > 0) {
        libc::rseq(state.rseq, state.rseq_len, state.flags, state.sig)
            .CONTEXT("Failed to set rseq")
            .TRY();
    }
    return {};
}

} // namespace rsequence
