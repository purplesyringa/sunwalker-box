use std::any::Any;
use std::collections::{hash_map, HashMap};
use std::num::NonZeroUsize;
use std::os::raw::c_void;
use std::os::unix::io::{OwnedFd, RawFd};

pub struct Serializer {
    data: Vec<u8>,
    fds: Option<Vec<RawFd>>,
    cyclic_ids: HashMap<*const c_void, NonZeroUsize>,
}

unsafe impl Send for Serializer {}

impl Serializer {
    pub fn new() -> Self {
        Serializer {
            data: Vec::new(),
            fds: Option::from(Vec::new()),
            cyclic_ids: HashMap::new(),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn serialize<T: Serialize + ?Sized>(&mut self, data: &T) {
        data.serialize_self(self);
    }

    pub fn add_fd(&mut self, fd: RawFd) -> usize {
        let fds = self
            .fds
            .as_mut()
            .expect("add_fd cannot be called after drain_fds");
        fds.push(fd);
        fds.len() - 1
    }

    pub fn drain_fds(&mut self) -> Vec<RawFd> {
        self.fds.take().expect("drain_fds can only be called once")
    }

    pub fn learn_cyclic(&mut self, ptr: *const c_void) -> Option<NonZeroUsize> {
        let len_before = self.cyclic_ids.len();
        match self.cyclic_ids.entry(ptr) {
            hash_map::Entry::Occupied(occupied) => Some(*occupied.get()),
            hash_map::Entry::Vacant(vacant) => {
                vacant.insert(NonZeroUsize::new(len_before + 1).expect("Too many cyclic objects"));
                None
            }
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl IntoIterator for Serializer {
    type Item = u8;
    type IntoIter = <Vec<u8> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

pub struct Deserializer {
    data: Vec<u8>,
    fds: Vec<Option<OwnedFd>>,
    pos: usize,
    cyclics: Vec<Box<dyn Any>>,
}

impl Deserializer {
    pub fn from(data: Vec<u8>, fds: Vec<OwnedFd>) -> Self {
        Deserializer {
            data,
            fds: fds.into_iter().map(|fd| Some(fd)).collect(),
            pos: 0,
            cyclics: Vec::new(),
        }
    }

    pub fn read(&mut self, data: &mut [u8]) {
        data.clone_from_slice(&self.data[self.pos..self.pos + data.len()]);
        self.pos += data.len();
    }

    pub fn deserialize<T: Deserialize>(&mut self) -> T {
        T::deserialize_self(self)
    }

    pub fn drain_fd(&mut self, idx: usize) -> OwnedFd {
        self.fds[idx]
            .take()
            .expect("drain_fd can only be called once for a particular index")
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn learn_cyclic<T: 'static>(&mut self, obj: T) {
        self.cyclics.push(Box::new(obj));
    }

    pub fn get_cyclic<T: 'static>(&self, id: NonZeroUsize) -> &T {
        self.cyclics[id.get() - 1]
            .downcast_ref()
            .expect("The cyclic object is of unexpected type")
    }
}

pub trait Serialize {
    fn serialize_self(&self, s: &mut Serializer);
}
pub trait Deserialize {
    fn deserialize_self(d: &mut Deserializer) -> Self;
}
pub trait DeserializeBoxed<'a> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a>;
}

pub trait Object: Serialize + Deserialize + Send + Sync {}
impl<T: Serialize + Deserialize + Send + Sync> Object for T {}

pub trait TraitObject: Serialize + for<'a> DeserializeBoxed<'a> + Send + Sync {}
impl<T: Serialize + Deserialize + for<'a> DeserializeBoxed<'a> + Send + Sync> TraitObject for T {}
