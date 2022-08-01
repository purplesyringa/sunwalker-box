use multiprocessing::tokio::{channel, duplex, Duplex, Receiver, Sender};
use multiprocessing::Object;

#[derive(Debug, PartialEq, Object)]
struct SimplePair {
    x: i32,
    y: i32,
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn simple() -> i64 {
    0x123456789abcdef
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn add_with_arguments(x: i32, y: i32) -> i32 {
    x + y
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn swap_complex_argument(pair: SimplePair) -> SimplePair {
    SimplePair {
        x: pair.y,
        y: pair.x,
    }
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn with_passed_rx(mut rx: Receiver<i32>) -> i32 {
    let a = rx.recv().await.unwrap().unwrap();
    let b = rx.recv().await.unwrap().unwrap();
    a - b
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn with_passed_tx(mut tx: Sender<i32>) -> () {
    tx.send(&5).await.unwrap();
    tx.send(&7).await.unwrap();
}

#[multiprocessing::entrypoint]
#[tokio::main]
async fn with_passed_duplex(mut chan: Duplex<i32, (i32, i32)>) -> () {
    while let Some((x, y)) = chan.recv().await.unwrap() {
        chan.send(&(x - y)).await.unwrap();
    }
}

#[multiprocessing::main]
#[tokio::main]
async fn main() {
    assert_eq!(
        simple
            .spawn_tokio()
            .await
            .unwrap()
            .join()
            .await
            .expect("simple failed"),
        0x123456789abcdef
    );
    println!("simple OK");

    assert_eq!(
        add_with_arguments
            .spawn_tokio(5, 7)
            .await
            .unwrap()
            .join()
            .await
            .expect("add_with_arguments failed"),
        12
    );
    println!("add_with_arguments OK");

    assert_eq!(add_with_arguments(5, 7).await, 12);
    println!("add_with_arguments call OK");

    assert_eq!(
        swap_complex_argument
            .spawn_tokio(SimplePair { x: 5, y: 7 })
            .await
            .unwrap()
            .join()
            .await
            .expect("swap_complex_argument failed"),
        SimplePair { x: 7, y: 5 }
    );
    println!("swap_complex_argument OK");

    {
        let (mut tx, rx) = channel::<i32>().unwrap();
        let mut child = with_passed_rx.spawn_tokio(rx).await.unwrap();
        tx.send(&5).await.unwrap();
        tx.send(&7).await.unwrap();
        assert_eq!(child.join().await.expect("with_passed_rx failed"), -2);
        println!("with_passed_rx OK");
    }

    {
        let (tx, mut rx) = channel::<i32>().unwrap();
        let mut child = with_passed_tx.spawn_tokio(tx).await.unwrap();
        assert_eq!(
            rx.recv().await.unwrap().unwrap() - rx.recv().await.unwrap().unwrap(),
            -2
        );
        child.join().await.unwrap();
        println!("with_passed_tx OK");
    }

    {
        let (mut local, downstream) = duplex::<(i32, i32), i32>().unwrap();
        let mut child = with_passed_duplex.spawn_tokio(downstream).await.unwrap();
        for (x, y) in [(5, 7), (100, -1), (53, 2354)] {
            local.send(&(x, y)).await.unwrap();
            assert_eq!(local.recv().await.unwrap().unwrap(), x - y);
        }
        drop(local);
        child.join().await.unwrap();
        println!("with_passed_duplex OK");
    }
}
