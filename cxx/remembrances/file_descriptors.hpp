#include "../libc.hpp"
#include <array>

namespace file_descriptors {

static constexpr size_t MAX_FILE_DESCRIPTORS = 10000;

enum class SavedFdKindDiscriminant : uint32_t {
    EVENT_FD,
    REGULAR,
};

union SavedFdKind {
    SavedFdKindDiscriminant discriminant;
    struct {
        SavedFdKindDiscriminant discriminant;
        uint32_t count;
    } event_fd;
    struct {
        SavedFdKindDiscriminant discriminant;
        int cloned_fd;
        uint64_t position;
    } regular;
};

struct SavedFd {
    int fd;
    int flags;
    SavedFdKind kind;
};

struct State {
    size_t count;
    std::array<SavedFd, MAX_FILE_DESCRIPTORS> fds;
};

// static Result<void> load(const State& state) {
//     for (size_t i = 0; i < state.count; i++) {
//         const SavedFd& fd = state.fds[i];
//         //
//         fd.fd
//     }
//     return {};
// }

} // namespace file_descriptors
