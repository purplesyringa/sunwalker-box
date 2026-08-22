fn main() {
    crossmist::init();
    if let Err(e) = sunwalker_box::entry::main() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
