use crate::{handles, Deserializer, Object, Serializer};
use std::default::Default;
use std::ffi::c_void;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use windows::Win32::System::Pipes;

pub trait TransmissibleObject: Object {}

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

fn send_on_handle<T: TransmissibleObject>(file: &mut File, value: &T) -> Result<()> {
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

    file.write_all(&serialized.len().to_ne_bytes())?;
    file.write_all(&serialized)?;
    Ok(())
}

fn recv_on_handle<T: TransmissibleObject>(file: &mut File) -> Result<Option<T>> {
    let mut len = [0u8; std::mem::size_of::<usize>()];
    if let Err(e) = file.read_exact(&mut len) {
        if e.kind() == ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let len = usize::from_ne_bytes(len);

    let mut serialized = vec![0u8; len];
    file.read_exact(&mut serialized)?;

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

    pub fn send(&mut self, value: &T) -> Result<()> {
        send_on_handle(&mut self.file, value)
    }
}

impl<T: TransmissibleObject> AsRawHandle for Sender<T> {
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

    pub fn recv(&mut self) -> Result<Option<T>> {
        recv_on_handle(&mut self.file)
    }
}

impl<T: TransmissibleObject> AsRawHandle for Receiver<T> {
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

    pub fn send(&mut self, value: &S) -> Result<()> {
        send_on_handle(&mut self.sender_file, value)
    }

    pub fn recv(&mut self) -> Result<Option<R>> {
        recv_on_handle(&mut self.receiver_file)
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
