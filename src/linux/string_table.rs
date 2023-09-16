macro_rules! table {
    ($fn_name:tt, $table_name:tt, $formatter:tt, $default_formatter:tt) => {
        pub fn $fn_name(number: i32) -> String {
            const INFO: (usize, usize) = unsafe {
                std::mem::transmute(*include_bytes!(concat!(
                    "../../target/",
                    $table_name,
                    ".info"
                )))
            };
            const TABLE_LENGTH: usize = INFO.0;
            const MAX_LENGTH: usize = INFO.1;
            static TABLE_OFFSETS: &[u16; TABLE_LENGTH] = unsafe {
                &std::mem::transmute(*include_bytes!(concat!(
                    "../../target/",
                    $table_name,
                    ".offsets"
                )))
            };
            static TABLE_NAMES: &[u8] =
                include_bytes!(concat!("../../target/", $table_name, ".names"));

            let number = number as usize;
            if number < TABLE_OFFSETS.len() {
                let data = TABLE_OFFSETS[number] as usize;
                if data != 0 {
                    let offset = data / (MAX_LENGTH + 1);
                    let length = data % (MAX_LENGTH + 1);
                    return format!($formatter, unsafe {
                        std::str::from_utf8_unchecked(&TABLE_NAMES[offset..offset + length])
                    });
                }
            }
            format!($default_formatter, number)
        }
    };
}

table!(syscall_no_to_name, "syscall_table", "{}", "syscall_0x{:x}");
table!(errno_to_name, "errno_table", "E{}", "E?? ({})");
