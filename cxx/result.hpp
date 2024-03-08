#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

struct Error {
    uint64_t _word;

    Error() : _word(0) {}
    Error(uint64_t word) : _word(word) {}

    Error context(size_t index) const { return (_word << 8) | index; }

    bool is_ok() const { return _word == 0; }

    int errno() const {
        uint64_t word = _word;
        while (word >= 0x10000) {
            word >>= 8;
        }
        return static_cast<uint16_t>(-word);
    }
};

template <typename T> struct [[nodiscard]] Result {
    Error _error;
    union {
        T _success_value;
    };

    Result() : _error{} {}
    Result(const Error &error) : _error(error) {}
    Result(const T &success_value) : _error{}, _success_value(success_value) {}
    Result(T &&success_value) : _error{}, _success_value(std::move(success_value)) {}

    Result(const Result &rhs)
        requires std::copy_constructible<T>
        : _error(rhs._error) {
        if (std::is_trivially_copy_constructible_v<T> || is_ok()) {
            new (&_success_value) T(rhs._success_value);
        }
    }
    Result(Result &&rhs) : _error(rhs._error) {
        if (std::is_trivially_move_constructible_v<T> || is_ok()) {
            new (&_success_value) T(std::move(rhs._success_value));
        }
    }

    ~Result() {
        if (is_ok()) {
            _success_value.~T();
        }
    }

    Result &operator=(const Result &rhs) = delete;
    Result &operator=(Result &&rhs) = delete;

    Result context(size_t index) && {
        if (is_ok()) {
            return std::move(*this);
        } else {
            return _error.context(index);
        }
    }

    T unwrap() && { return std::move(_success_value); }

    bool is_ok() const { return _error.is_ok(); }

    bool is_errno(int errno) const { return _error.errno() == errno; }

    Result swallow(int errno, const T &def) && {
        if (is_errno(errno)) {
            return def;
        } else {
            return std::move(*this);
        }
    }
};

template <> struct [[nodiscard]] Result<void> {
    Error _error;

    Result() : _error{} {}
    Result(const Error &error) : _error(error) {}

    Result context(size_t index) && {
        if (is_ok()) {
            return {};
        } else {
            return _error.context(index);
        }
    }

    void unwrap() && {}

    bool is_ok() const { return _error.is_ok(); }

    Result swallow(int errno) && {
        if (_error.errno() == errno) {
            return {};
        } else {
            return std::move(*this);
        }
    }
};

#define TRY(result)                                                                                \
    ({                                                                                             \
        auto res = (result);                                                                       \
        if (!res.is_ok()) {                                                                        \
            return res._error;                                                                     \
        }                                                                                          \
        std::move(res).unwrap();                                                                   \
    })

// This is a horrible hack. I don't give a fuck.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wnon-template-friend"
template <size_t N> struct ContextReader {
    friend constexpr auto context_read(ContextReader);
};
#pragma GCC diagnostic pop

template <size_t N, typename Text> struct ContextWriter {
    friend constexpr auto context_read(ContextReader<N>) { return Text{}; }
    static constexpr size_t index = N;
};

template <size_t N, typename Text> constexpr size_t get_context_index(float) {
    return ContextWriter<N, Text>::index;
}

template <size_t N, typename Text, auto = context_read(ContextReader<N>{})>
constexpr size_t get_context_index(int) {
    return get_context_index<N + 1, Text>(0);
}

template <typename T, T... Chars> constexpr size_t operator""_context() {
    return get_context_index<0, std::integer_sequence<T, Chars..., 0>>(0);
}

#define CONTEXT(text) context(text##_context)
#define ANYHOW(text) Error{0x8000}.CONTEXT(text)
#define BAIL(text)                                                                                 \
    do {                                                                                           \
        return ANYHOW(text);                                                                       \
    } while (0)
#define ENSURE(cond, text)                                                                         \
    if (!(cond))                                                                                   \
    BAIL(text)

template <typename T, T... A, T... B>
constexpr std::integer_sequence<T, A..., B...> concat(std::integer_sequence<T, A...>,
                                                      std::integer_sequence<T, B...>) {
    return {};
}

template <size_t N, auto... Texts>
constexpr std::array<char, sizeof...(Texts)>
create_context_map(float, std::integer_sequence<char, Texts...>) {
    return {Texts...};
}

template <size_t N, auto... Texts, auto CurrentText = context_read(ContextReader<N>{})>
constexpr auto create_context_map(int, std::integer_sequence<char, Texts...> texts) {
    return create_context_map<N + 1>(0, concat(texts, CurrentText));
}

#define FINALIZE_CONTEXTS                                                                          \
    auto result_context_map __attribute__((section(".result_context_map"), externally_visible)) =  \
        create_context_map<0>(0, std::integer_sequence<char>{});
