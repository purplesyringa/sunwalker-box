pub auto trait PlainOldData {}

impl<T> !PlainOldData for &T {}
impl<T> !PlainOldData for &mut T {}
impl<T> !PlainOldData for *const T {}
impl<T> !PlainOldData for *mut T {}

pub trait ReportPlainOldData {
    const IS_POD: bool;
}

impl<T> ReportPlainOldData for T {
    default const IS_POD: bool = false;
}

impl<T: PlainOldData> ReportPlainOldData for T {
    const IS_POD: bool = true;
}
