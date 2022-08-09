use crate::handles::{OwnedHandle, RawHandle};
use std::any::Any;
use std::collections::{hash_map, HashMap};
use std::num::NonZeroUsize;
use std::os::raw::c_void;

pub struct Serializer {
    data: Vec<u8>,
    handles: Option<Vec<RawHandle>>,
    cyclic_ids: HashMap<*const c_void, NonZeroUsize>,
}

impl Serializer {
    pub fn new() -> Self {
        Serializer {
            data: Vec::new(),
            handles: Option::from(Vec::new()),
            cyclic_ids: HashMap::new(),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn serialize<T: Object + ?Sized>(&mut self, data: &T) {
        data.serialize_self(self);
    }

    pub fn add_handle(&mut self, handle: RawHandle) -> usize {
        let handles = self
            .handles
            .as_mut()
            .expect("add_handle cannot be called after drain_handles");
        handles.push(handle);
        handles.len() - 1
    }

    pub fn drain_handles(&mut self) -> Vec<RawHandle> {
        self.handles
            .take()
            .expect("drain_handles can only be called once")
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
    handles: Vec<Option<OwnedHandle>>,
    pos: usize,
    cyclics: Vec<Box<dyn Any>>,
}

impl Deserializer {
    pub fn from(data: Vec<u8>, handles: Vec<OwnedHandle>) -> Self {
        Deserializer {
            data,
            handles: handles.into_iter().map(|handle| Some(handle)).collect(),
            pos: 0,
            cyclics: Vec::new(),
        }
    }

    pub fn read(&mut self, data: &mut [u8]) {
        data.clone_from_slice(&self.data[self.pos..self.pos + data.len()]);
        self.pos += data.len();
    }

    pub fn deserialize<T: Object>(&mut self) -> T {
        T::deserialize_self(self)
    }

    pub fn drain_handle(&mut self, idx: usize) -> OwnedHandle {
        self.handles[idx]
            .take()
            .expect("drain_handle can only be called once for a particular index")
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

pub trait Object {
    fn serialize_self(&self, s: &mut Serializer);
    fn deserialize_self(d: &mut Deserializer) -> Self
    where
        Self: Sized;
    fn deserialize_on_heap<'a>(&self, d: &mut Deserializer) -> Box<dyn Object + 'a>
    where
        Self: 'a;
}
