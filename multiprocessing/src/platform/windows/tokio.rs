use crate::{
    handles, handles::OwnedHandle, subprocess, Deserializer, FnOnceObject, Object, Serializer,
    TransmissibleObject,
};
use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::marker::PhantomData;
use std::os::windows::{
    io,
    io::{FromRawHandle, RawHandle},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};
use windows::Win32::System::{Pipes, Threading, WindowsProgramming};

#[derive(Object)]
pub struct Sender<T: TransmissibleObject> {
    file: File,
    marker: PhantomData<fn(T) -> T>,
}

#[derive(Object)]
pub struct Receiver<T: TransmissibleObject> {
    file: File,
    marker: PhantomData<fn(T) -> T>,
}

#[derive(Object)]
pub struct Duplex<S: TransmissibleObject, R: TransmissibleObject> {
    sender_file: File,
    receiver_file: File,
    marker: PhantomData<fn(S, R) -> (S, R)>,
}

pub fn channel<T: TransmissibleObject>() -> Result<(Sender<T>, Receiver<T>)> {
    let mut tx: handles::RawHandle = Default::default();
    let mut rx: handles::RawHandle = Default::default();
    unsafe {
        Pipes::CreatePipe(
            &mut rx as *mut handles::RawHandle,
            &mut tx as *mut handles::RawHandle,
            std::ptr::null(),
            0,
        )
        .ok()?;
    }
    let tx = Sender {
        file: unsafe { File::from_raw_handle(tx.0 as *mut c_void) },
        marker: PhantomData,
    };
    let rx = Receiver {
        file: unsafe { File::from_raw_handle(rx.0 as *mut c_void) },
        marker: PhantomData,
    };
    Ok((tx, rx))
}

pub fn duplex<A: TransmissibleObject, B: TransmissibleObject>(
) -> Result<(Duplex<A, B>, Duplex<B, A>)> {
    let (tx_a, rx_a) = channel::<A>()?;
    let (tx_b, rx_b) = channel::<B>()?;
    let ours = Duplex {
        sender_file: tx_a.file,
        receiver_file: rx_b.file,
        marker: PhantomData,
    };
    let theirs = Duplex {
        sender_file: tx_b.file,
        receiver_file: rx_a.file,
        marker: PhantomData,
    };
    Ok((ours, theirs))
}

async fn send_on_handle<T: TransmissibleObject>(file: &mut File, value: &T) -> Result<()> {
    let mut s = Serializer::new();
    s.serialize(value);

    let handles = s.drain_handles();
    if !handles.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            "The impossible happened: a transmissible message contains attached handles",
        ));
    }

    let serialized = s.into_vec();
    file.write_all(&serialized.len().to_ne_bytes()).await?;
    file.write_all(&serialized).await
}

async fn recv_on_handle<T: TransmissibleObject>(file: &mut File) -> Result<Option<T>> {
    let mut len = [0u8; std::mem::size_of::<usize>()];
    if let Err(e) = file.read_exact(&mut len).await {
        if e.kind() == ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let len = usize::from_ne_bytes(len);

    let mut serialized = vec![0u8; len];
    file.read_exact(&mut serialized).await?;

    let mut d = Deserializer::from(serialized, Vec::new());
    Ok(Some(d.deserialize()))
}

impl<T: TransmissibleObject> Sender<T> {
    pub fn from_file(file: File) -> Self {
        Sender {
            file,
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, value: &T) -> Result<()> {
        send_on_handle(&mut self.file, value).await
    }
}

impl<T: TransmissibleObject> io::AsRawHandle for Sender<T> {
    fn as_raw_handle(&self) -> RawHandle {
        self.file.as_raw_handle()
    }
}

impl<T: TransmissibleObject> FromRawHandle for Sender<T> {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self::from_file(File::from_raw_handle(handle))
    }
}

impl<T: TransmissibleObject> Receiver<T> {
    pub fn from_file(file: File) -> Self {
        Receiver {
            file,
            marker: PhantomData,
        }
    }

    pub async fn recv(&mut self) -> Result<Option<T>> {
        recv_on_handle(&mut self.file).await
    }
}

impl<T: TransmissibleObject> io::AsRawHandle for Receiver<T> {
    fn as_raw_handle(&self) -> RawHandle {
        self.file.as_raw_handle()
    }
}

impl<T: TransmissibleObject> FromRawHandle for Receiver<T> {
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self::from_file(File::from_raw_handle(handle))
    }
}

impl<S: TransmissibleObject, R: TransmissibleObject> Duplex<S, R> {
    pub fn from_files(sender_file: File, receiver_file: File) -> Self {
        Duplex {
            sender_file,
            receiver_file,
            marker: PhantomData,
        }
    }

    pub fn join(sender: Sender<S>, receiver: Receiver<R>) -> Self {
        Duplex {
            sender_file: sender.file,
            receiver_file: receiver.file,
            marker: PhantomData,
        }
    }

    pub async fn send(&mut self, value: &S) -> Result<()> {
        send_on_handle(&mut self.sender_file, value).await
    }

    pub async fn recv(&mut self) -> Result<Option<R>> {
        recv_on_handle(&mut self.receiver_file).await
    }

    pub fn into_sender(self) -> Sender<S> {
        Sender {
            file: self.sender_file,
            marker: PhantomData,
        }
    }

    pub fn into_receiver(self) -> Receiver<R> {
        Receiver {
            file: self.receiver_file,
            marker: PhantomData,
        }
    }

    pub fn split(self) -> (Sender<S>, Receiver<R>) {
        (
            Sender {
                file: self.sender_file,
                marker: PhantomData,
            },
            Receiver {
                file: self.receiver_file,
                marker: PhantomData,
            },
        )
    }
}

pub struct Child<T: TransmissibleObject> {
    proc_handle: OwnedHandle,
    output_rx: Receiver<T>,
}

impl<T: TransmissibleObject> Child<T> {
    pub fn new(proc_handle: OwnedHandle, output_rx: Receiver<T>) -> Child<T> {
        Child {
            proc_handle,
            output_rx,
        }
    }

    pub fn kill(&mut self) -> Result<()> {
        use handles::AsRawHandle;
        unsafe {
            Threading::TerminateProcess(self.proc_handle.as_raw_handle(), 1).ok()?;
        }
        Ok(())
    }

    pub fn id(&self) -> handles::RawHandle {
        use handles::AsRawHandle;
        self.proc_handle.as_raw_handle()
    }

    pub async fn join(&mut self) -> Result<T> {
        use handles::AsRawHandle;
        let value = self.output_rx.recv().await?;
        // This is synchronous, but should be really fast
        if unsafe {
            Threading::WaitForSingleObject(
                self.proc_handle.as_raw_handle(),
                WindowsProgramming::INFINITE,
            )
        } == u32::MAX
        {
            return Err(Error::last_os_error());
        }
        let mut code: u32 = 0;
        unsafe {
            Threading::GetExitCodeProcess(self.proc_handle.as_raw_handle(), &mut code as *mut u32)
                .ok()?;
        }
        if code == 0 {
            value.ok_or_else(|| {
                Error::new(
                    ErrorKind::Other,
                    "The subprocess terminated without returning a value",
                )
            })
        } else {
            Err(Error::new(
                ErrorKind::Other,
                format!("The subprocess terminated with exit code {code}"),
            ))
        }
    }
}

pub async unsafe fn spawn<T: TransmissibleObject>(
    entry: Box<dyn FnOnceObject<(handles::RawHandle,), Output = i32>>,
    flags: subprocess::Flags,
) -> Result<Child<T>> {
    use handles::AsRawHandle;

    let mut s = Serializer::new();
    s.serialize(&entry);

    let handles = s.drain_handles();

    let (mut local, child) = duplex::<(Vec<u8>, Vec<handles::RawHandle>), T>()?;
    let (child_tx, child_rx) = child.split();
    let handle = subprocess::_spawn_child(
        child_tx.as_raw_handle(),
        child_rx.as_raw_handle(),
        flags,
        &handles,
    )?;
    local.send(&(s.into_vec(), handles)).await?;

    Ok(Child::new(handle, local.into_receiver()))
}
