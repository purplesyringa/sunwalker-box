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

Error _global_error;

template <typename Result, typename T> struct _result_base {
    Error _error;
    _result_base() : _error{} {}
    _result_base(Error error) : _error(error) {}

    Result context(size_t index) && {
        if (is_ok()) {
            return static_cast<Result &&>(*this);
        } else {
            return _error.context(index);
        }
    }

    bool is_ok() const { return _error.is_ok(); }

    int unwrap_errno() const {
        int errno = _error.errno();
        if (errno == 0) {
            __builtin_unreachable();
        }
        return errno;
    }

    bool is_errno(int errno) const { return _error.errno() == errno; }

    Result _bind_global() && {
        _global_error = _error;
        return static_cast<Result &&>(*this);
    }
    Result _bind_global() const & {
        _global_error = _error;
        return static_cast<const Result &>(*this);
    }

    T _unwrap_int(int) && { return static_cast<Result &&>(*this).unwrap(); }
};

template <typename T> struct [[nodiscard]] Result : _result_base<Result<T>, T> {
    using Base = _result_base<Result<T>, T>;
    using Base::Base;

    union {
        T _success_value;
    };

    Result(const T &success_value) : _success_value(success_value) {}
    Result(T &&success_value) : _success_value(std::move(success_value)) {}

    Result(const Result &rhs)
        requires std::copy_constructible<T>
        : Base(rhs._error) {
        if (std::is_trivially_copy_constructible_v<T> || this->is_ok()) {
            new (&_success_value) T(rhs._success_value);
        }
    }
    Result(Result &&rhs) : Base(rhs._error) {
        if (std::is_trivially_move_constructible_v<T> || this->is_ok()) {
            new (&_success_value) T(std::move(rhs._success_value));
        }
    }

    ~Result() {
        if (this->is_ok()) {
            _success_value.~T();
        }
    }

    Result &operator=(const Result &rhs) = delete;
    Result &operator=(Result &&rhs) = delete;

    T unwrap() && { return std::move(_success_value); }

    Result swallow(int errno, const T &def) && {
        if (this->is_errno(errno)) {
            return def;
        } else {
            return std::move(*this);
        }
    }
};

template <> struct [[nodiscard]] Result<void> : _result_base<Result<void>, void> {
    using _result_base<Result<void>, void>::_result_base;

    void unwrap() && {}

    Result swallow(int errno) && {
        if (is_errno(errno)) {
            return {};
        } else {
            return std::move(*this);
        }
    }
};

// Even though _global_error is global, it is implicitly static and thus is subject to storage
// optimization. The generated code uses only registers.
#define TRY()                                                                                      \
    _bind_global()._unwrap_int(({                                                                  \
        if (!_global_error.is_ok()) {                                                              \
            return _global_error;                                                                  \
        }                                                                                          \
        0;                                                                                         \
    }))

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
