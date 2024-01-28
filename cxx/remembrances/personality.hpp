#include "../libc.hpp"

// Holy echopraxia

#ifdef __aarch64__
namespace libc {
Result<long> personality(int persona) { return arm64_personality(persona); }
} // namespace libc
#endif

namespace personality {

using State = long;

Result<void> save(State &state) {
    state = libc::personality(0xffffffff).TRY();
    return {};
}

Result<void> load(const State &state) {
    libc::personality(state).TRY();
    return {};
}

} // namespace personality
