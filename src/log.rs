use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};

pub static DIAGNOSTICS_NAMESPACE: AtomicPtr<&'static str> = AtomicPtr::new(null_mut());

#[macro_export]
macro_rules! log_style {
    (notice) => {
        ("", "")
    };
    (warn) => {
        ("\x1b[33m", "")
    };
    (impossible) => {
        (
            "\x1b[31m",
            "sunwalker has encountered a situation that should have been impossible. It has been \
             configured to attempt to handle it gracefully, but all guarantees are off because \
             this case is untested, and the maintainers might remove this in the future. Please \
             report this as a bug, because it is one and we really want to know if this code is \
             reachable. The error is:\n\n",
        )
    };
}

#[macro_export]
macro_rules! log {
    ($format:literal $($rest:tt)*) => {
        log!(notice, $format $($rest)*);
    };
    ($style:ident, $($args:tt)*) => {
        {
            let ns = $crate::log::DIAGNOSTICS_NAMESPACE.load(::std::sync::atomic::Ordering::Acquire);
            if !ns.is_null() {
                let ns = unsafe { *ns };

                let context = file!().strip_suffix(".rs").unwrap();
                let context = context.rsplit_once('/').map(|(_, x)| x).unwrap_or(context);
                let context = format!("{ns}:{context}");

                use ::std::hash::{Hash, Hasher};
                let mut hasher = ::std::collections::hash_map::DefaultHasher::new();
                context.hash(&mut hasher);
                let hash = hasher.finish() as usize;

                let colors = [
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
                    (255, 0, 85)
                ];
                let (r, g, b) = colors[hash % colors.len()];

                let (prefix_formatting, prefix_text) = $crate::log_style!($style);

                let text = $crate::log::word_wrap(&format!("{prefix_text}{}", format_args!($($args)*)));

                // Failing to log is not considered a failure, because panicking in a critical
                // section or a cleanup procedure might lead to worse results.
                use ::std::io::Write;
                let mut stderr = ::std::io::stderr();
                let _ = writeln!(
                    stderr,
                    "\x1b[38;2;{r};{g};{b}m[{context:15}]\x1b[0m {prefix_formatting}{text}\x1b[0m"
                );
            }
        }
    };
}

#[macro_export]
macro_rules! enable_diagnostics {
    ($ns:literal) => {
        unsafe {
            static NS: &'static str = $ns;
            $crate::log::enable_diagnostics(&NS as *const _ as *mut _)
        }
    };
}

pub fn diagnostics_enabled() -> bool {
    !DIAGNOSTICS_NAMESPACE.load(Ordering::Acquire).is_null()
}

pub unsafe fn enable_diagnostics(ns: *mut &'static str) {
    DIAGNOSTICS_NAMESPACE.store(ns, Ordering::Release)
}

pub fn word_wrap(text: &str) -> String {
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
