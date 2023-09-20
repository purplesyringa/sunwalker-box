use crossmist::Object;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

pub struct DiagnosticsConfig {
    pub namespace: &'static str,
    pub level: LogLevel,
}

#[derive(Clone, Copy, Object, PartialEq, PartialOrd)]
pub enum LogLevel {
    Notice,
    Warn,
    Impossible,
    None,
}

impl LogLevel {
    fn get_prefix_formatting(self) -> &'static str {
        match self {
            Self::Notice => "",
            Self::Warn => "\x1b[33m",
            Self::Impossible => "\x1b[31m",
            Self::None => unreachable!(),
        }
    }

    fn get_prefix_text(self) -> &'static str {
        match self {
            Self::Notice | Self::Warn => "",
            Self::Impossible => {
                "sunwalker has encountered a situation that should have been impossible. It has \
                 been configured to attempt to handle it gracefully, but all guarantees are off \
                 because this case is untested, and the maintainers might remove this in the \
                 future. Please report this as a bug, because it is one and we really want to know \
                 if this code is reachable. The error is:\n\n"
            }
            Self::None => unreachable!(),
        }
    }
}

static DIAGNOSTICS_CONFIG: AtomicPtr<DiagnosticsConfig> = AtomicPtr::new(null_mut());

#[macro_export]
macro_rules! log_level {
    (notice) => {
        $crate::log::LogLevel::Notice
    };
    (warn) => {
        $crate::log::LogLevel::Warn
    };
    (impossible) => {
        $crate::log::LogLevel::Impossible
    };
    (none) => {
        $crate::log::LogLevel::None
    };
}

#[macro_export]
macro_rules! log {
    ($format:literal $($rest:tt)*) => {
        log!(notice, $format $($rest)*);
    };
    ($level:ident, $($args:tt)*) => {
        $crate::log::do_log(
            $crate::log_level!($level),
            file!(),
            || format!($($args)*),
        );
    };
}

pub fn enable_diagnostics(namespace: &'static str, level: LogLevel) {
    let config = Box::leak(Box::new(DiagnosticsConfig { namespace, level }));
    DIAGNOSTICS_CONFIG.store(config as *mut _, Ordering::Release);
}

static COLORS: [(u8, u8, u8); 23] = [
    (255, 0, 0),
    (255, 42, 0),
    (255, 85, 0),
    (255, 128, 0),
    (255, 170, 0),
    (255, 213, 0),
    (255, 255, 0),
    (212, 255, 0),
    (170, 255, 0),
    (128, 255, 0),
    (0, 255, 0),
    (0, 255, 85),
    (0, 255, 170),
    (0, 255, 213),
    (0, 255, 255),
    (0, 213, 255),
    (0, 170, 255),
    (127, 0, 255),
    (170, 0, 255),
    (212, 0, 255),
    (255, 0, 255),
    (255, 0, 170),
    (255, 0, 85),
];

pub fn do_log(level: LogLevel, file: &'static str, args: impl FnOnce() -> String) {
    let config = get_diagnostics_config();
    if level < config.level {
        return;
    }

    let context = file.strip_suffix(".rs").unwrap();
    let context = context.rsplit_once('/').map(|(_, x)| x).unwrap_or(context);
    let context = format!("{}:{context}", config.namespace);

    let mut hasher = DefaultHasher::new();
    context.hash(&mut hasher);
    let hash = hasher.finish() as usize;
    let (r, g, b) = COLORS[hash % COLORS.len()];

    let text = word_wrap(&format!("{}{}", level.get_prefix_text(), args()));

    // Failing to log is not considered a failure, because panicking in a critical section or a
    // cleanup procedure might lead to worse results
    let _ = writeln!(
        std::io::stderr(),
        "\x1b[38;2;{r};{g};{b}m[{context:15}]\x1b[0m {}{text}\x1b[0m",
        level.get_prefix_formatting(),
    );
}

pub fn get_diagnostics_config() -> &'static DiagnosticsConfig {
    unsafe { &*DIAGNOSTICS_CONFIG.load(Ordering::Acquire) }
}

fn word_wrap(text: &str) -> String {
    const NEWLINE: &str = "\n                  ";
    let mut res = String::new();
    let mut line_length = 0;
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            res.push_str(NEWLINE);
            line_length = 0;
        }
        for word in line.split_whitespace() {
            if line_length + 1 + word.len() <= 100 {
                if line_length > 0 {
                    res.push(' ');
                }
                res.push_str(word);
                line_length += 1 + word.len();
            } else {
                res.push_str(NEWLINE);
                res.push_str(word);
                line_length = 1 + word.len();
            }
        }
    }
    res
}
