#[multiprocessing::main]
#[tokio::main(flavor = "current_thread")] // namespaces don't work well with multiple threads
async fn main() {
    sunwalker_box::entry::main().await;
}
