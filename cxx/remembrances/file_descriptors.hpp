#include "../libc.hpp"
#include <array>

namespace file_descriptors {

static constexpr size_t MAX_FILE_DESCRIPTORS = 10000;

enum class SavedFdKindDiscriminant : uint32_t {
    EVENT_FD,
    REGULAR,
    DIRECTORY,
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
    struct {
        SavedFdKindDiscriminant discriminant;
        int cloned_fd;
        uint64_t position;
    } directory;
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

// Returns "/proc/self/fd/{fd}", null-terminated
const char *format_fd_path(unsigned fd) {
    // Pad prefix to 16 bytes at the start -- this improves memcpy
    static constexpr std::array prefix{'\0', '\0', '/', 'p', 'r', 'o', 'c', '/',
                                       's',  'e',  'l', 'f', '/', 'f', 'd', '/'};
    static std::array<char, prefix.size() + 11> buf;
    char *path = buf.data() + buf.size() - 1;
    // path currently points at the null terminator
    do {
        *--path = '0' + fd % 10;
        fd /= 10;
    } while (fd > 0);
    __builtin_memcpy(path - prefix.size(), prefix.data(), prefix.size());
    return path - 14; // length of /proc/self/fd/
}

Result<void> load(const State &state) {
    for (size_t i = 0; i < state.count; i++) {
        const SavedFd &fd = state.fds[i];

        int new_fd;
        switch (fd.kind.discriminant) {
        case SavedFdKindDiscriminant::EVENT_FD:
            new_fd = libc::eventfd2(fd.kind.event_fd.count, fd.flags & ~O_ACCMODE)
                         .CONTEXT("Failed to create eventfd")
                         .TRY();
            break;
        case SavedFdKindDiscriminant::REGULAR: {
            const char *path = format_fd_path(fd.kind.regular.cloned_fd);
            new_fd = libc::openat(AT_FDCWD, path, fd.flags, 0)
                         .CONTEXT("Failed to open regular fd")
                         .TRY();
            libc::lseek(new_fd, fd.kind.regular.position, SEEK_SET)
                .CONTEXT("Failed to seek regular fd")
                .TRY();
            libc::close(fd.kind.regular.cloned_fd).CONTEXT("failed to close cloned fd").TRY();
            break;
        }
        case SavedFdKindDiscriminant::DIRECTORY: {
            // If the filesystem is reset between suspend and resume, the fds are going to point at
            // files in the old filesystem. If that's a read-only regular file, it's not really a
            // problem, but if it's a directory, it can be used with openat to obtain an fd to a
            // writable file in the wrong filesystem, which is utterly wrong and, as if that's not
            // enough, enables data sharing between runs. Therefore, resolve the path the fd points
            // to and open that path manually
            const char *path = format_fd_path(fd.kind.directory.cloned_fd);
            static char real_path[4096];
            ssize_t n_bytes = libc::readlinkat(AT_FDCWD, path, real_path, sizeof(real_path))
                                  .CONTEXT("Failed to readlink")
                                  .TRY();
            // Suspend happens before the user has any possibility of modifying the filesystem.
            // Let's hope that at least the chroot environment is safe in this fashion
            ENSURE(n_bytes < sizeof(real_path), "Too long filesystem path");
            real_path[n_bytes] = '\0';

            new_fd = libc::openat(AT_FDCWD, real_path, fd.flags, 0)
                         .CONTEXT("Failed to open directory fd")
                         .TRY();
            libc::lseek(new_fd, fd.kind.directory.position, SEEK_SET)
                .CONTEXT("Failed to seek directory fd")
                .TRY();
            libc::close(fd.kind.directory.cloned_fd).CONTEXT("failed to close cloned fd").TRY();
            break;
        }
        default:
            BAIL("Invalid saved fd discriminant");
        }

        // Fix fd
        if (new_fd != fd.fd) {
            libc::dup3(new_fd, fd.fd, fd.flags & O_CLOEXEC)
                .CONTEXT("Failed to dup3 new file descriptor")
                .TRY();
            libc::close(new_fd).CONTEXT("Failed to close new file descriptor").TRY();
        }
    }

    return {};
}

} // namespace file_descriptors
