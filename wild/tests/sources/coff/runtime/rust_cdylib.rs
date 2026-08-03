#[no_mangle]
pub extern "C" fn rust_exported(left: i32, right: i32) -> i32 {
    let values = vec![left, right, 3];
    values.into_iter().sum()
}
