#[crossmist::main]
fn main() {
    if let Err(e) = sunwalker_box::entry::main() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
