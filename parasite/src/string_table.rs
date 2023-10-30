macro_rules! table {
    ($fn_name:tt, $table_name:tt) => {
        pub fn $fn_name(number: i32) -> Option<&'static str> {
            const INFO: (usize, usize) = unsafe {
                core::mem::transmute(*include_bytes!(concat!(
                    "../../target/",
                    $table_name,
                    ".info"
                )))
            };
            const TABLE_LENGTH: usize = INFO.0;
            const MAX_LENGTH: usize = INFO.1;
            static TABLE_OFFSETS: &[u16; TABLE_LENGTH] = unsafe {
                &core::mem::transmute(*include_bytes!(concat!(
                    "../../target/",
                    $table_name,
                    ".offsets"
                )))
            };
            static TABLE_NAMES: &[u8] =
                include_bytes!(concat!("../../target/", $table_name, ".names"));

            let number = number as usize;
            if let Some(data) = TABLE_OFFSETS.get(number) {
                let data = *data as usize;
                if data != 0 {
                    let offset = data / (MAX_LENGTH + 1);
                    let length = data % (MAX_LENGTH + 1);
                    return Some(unsafe {
                        core::str::from_utf8_unchecked(TABLE_NAMES.get_unchecked(offset..offset + length))
                    });
                }
            }
            None
        }
    };
}

table!(errno_to_name, "errno_table");
