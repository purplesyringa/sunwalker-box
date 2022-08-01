use crate::{Deserialize, DeserializeBoxed, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, LinkedList, VecDeque};
use std::hash::{BuildHasher, Hash};
use std::os::raw::c_void;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::Arc;

impl Serialize for bool {
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(&(*self as u8));
    }
}
impl Deserialize for bool {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        d.deserialize::<u8>() != 0
    }
}
impl<'a> DeserializeBoxed<'a> for bool {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for char {
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(&(*self as u32))
    }
}
impl Deserialize for char {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        char::from_u32(d.deserialize::<u32>()).unwrap()
    }
}
impl<'a> DeserializeBoxed<'a> for char {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl<T> Serialize for std::marker::PhantomData<T> {
    fn serialize_self(&self, _s: &mut Serializer) {}
}
impl<T> Deserialize for std::marker::PhantomData<T> {
    fn deserialize_self(_d: &mut Deserializer) -> Self {
        Self {}
    }
}
impl<'a, T: 'a> DeserializeBoxed<'a> for std::marker::PhantomData<T> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for String {
    fn serialize_self(&self, s: &mut Serializer) {
        // XXX: unnecessary heap usage
        s.serialize(&Vec::from(self.as_bytes()))
    }
}
impl Deserialize for String {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        // XXX: unnecessary heap usage
        std::str::from_utf8(&d.deserialize::<Vec<u8>>())
            .expect("Failed to deserialize string")
            .to_string()
    }
}
impl<'a> DeserializeBoxed<'a> for String {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::ffi::CString {
    fn serialize_self(&self, s: &mut Serializer) {
        // XXX: unnecessary heap usage
        s.serialize(&Vec::from(self.as_bytes()))
    }
}
impl Deserialize for std::ffi::CString {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        // XXX: unnecessary heap usage
        Self::new(
            std::str::from_utf8(&d.deserialize::<Vec<u8>>())
                .expect("Failed to deserialize CString (UTF-8 decoding)"),
        )
        .expect("Failed to deserialize CString (null byte in the middle)")
    }
}
impl<'a> DeserializeBoxed<'a> for std::ffi::CString {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::ffi::OsString {
    fn serialize_self(&self, s: &mut Serializer) {
        // XXX: unnecessary heap usage
        s.serialize(&self.clone().into_vec())
    }
}
impl Deserialize for std::ffi::OsString {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        Self::from_vec(d.deserialize())
    }
}
impl<'a> DeserializeBoxed<'a> for std::ffi::OsString {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for () {
    fn serialize_self(&self, _s: &mut Serializer) {}
}
impl Deserialize for () {
    fn deserialize_self(_d: &mut Deserializer) -> Self {
        ()
    }
}
impl<'a> DeserializeBoxed<'a> for () {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for ! {
    fn serialize_self(&self, _s: &mut Serializer) {
        unreachable!()
    }
}
impl Deserialize for ! {
    fn deserialize_self(_d: &mut Deserializer) -> Self {
        unreachable!()
    }
}
impl<'a> DeserializeBoxed<'a> for ! {
    fn deserialize_on_heap(&self, _d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        unreachable!()
    }
}

impl<T: Serialize, U: Serialize> Serialize for (T, U) {
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(&self.0);
        s.serialize(&self.1);
    }
}
impl<T: Deserialize, U: Deserialize> Deserialize for (T, U) {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let a = d.deserialize();
        let b = d.deserialize();
        (a, b)
    }
}
impl<'a, T: 'a + Deserialize, U: 'a + Deserialize> DeserializeBoxed<'a> for (T, U) {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl<T: Serialize> Serialize for Option<T> {
    fn serialize_self(&self, s: &mut Serializer) {
        match self {
            None => s.serialize(&false),
            Some(ref x) => {
                s.serialize(&true);
                s.serialize(x);
            }
        }
    }
}
impl<T: Deserialize> Deserialize for Option<T> {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        if d.deserialize::<bool>() {
            Some(d.deserialize())
        } else {
            None
        }
    }
}
impl<'a, T: 'a + Deserialize> DeserializeBoxed<'a> for Option<T> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

trait BaseTrait {}

struct BaseType;

impl BaseTrait for BaseType {}

fn extract_vtable_ptr<T: ?Sized>(metadata: &std::ptr::DynMetadata<T>) -> *const () {
    // Yeah, screw me
    unsafe { *(metadata as *const std::ptr::DynMetadata<T> as *const *const ()) }
}

fn get_base_vtable_ptr() -> *const () {
    extract_vtable_ptr(&std::ptr::metadata(&BaseType as &dyn BaseTrait))
}

impl<T: ?Sized> Serialize for std::ptr::DynMetadata<T> {
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(
            &(extract_vtable_ptr(&self) as usize).wrapping_sub(get_base_vtable_ptr() as usize),
        );
    }
}
impl<T: ?Sized> Deserialize for std::ptr::DynMetadata<T> {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let vtable_ptr = d
            .deserialize::<usize>()
            .wrapping_add(get_base_vtable_ptr() as usize) as *const ();
        let mut metadata: std::mem::MaybeUninit<Self> = std::mem::MaybeUninit::uninit();
        unsafe {
            *(metadata.as_mut_ptr() as *mut std::ptr::DynMetadata<T> as *mut *const ()) =
                vtable_ptr;
            metadata.assume_init()
        }
    }
}
impl<'a, T: 'a + ?Sized> DeserializeBoxed<'a> for std::ptr::DynMetadata<T> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl<T: Serialize + std::ptr::Pointee + ?Sized> Serialize for Box<T>
where
    T::Metadata: Serialize,
{
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(&std::ptr::metadata(self.as_ref()));
        self.as_ref().serialize_self(s);
    }
}
impl<'a, T: DeserializeBoxed<'a> + std::ptr::Pointee + ?Sized> Deserialize for Box<T>
where
    T::Metadata: Deserialize,
{
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let metadata = d.deserialize::<T::Metadata>();
        let data_ptr = unsafe {
            Box::into_raw(
                (*std::ptr::from_raw_parts::<T>(std::ptr::null(), metadata)).deserialize_on_heap(d),
            )
        };
        // Switch vtable
        let fat_ptr = std::ptr::from_raw_parts_mut(data_ptr.to_raw_parts().0, metadata);
        unsafe { Box::from_raw(fat_ptr) }
    }
}
impl<'a, T: 'a + DeserializeBoxed<'a> + std::ptr::Pointee + ?Sized> DeserializeBoxed<'a> for Box<T>
where
    T::Metadata: Deserialize,
{
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl<'a, T: 'a + Serialize> Serialize for Rc<T> {
    fn serialize_self(&self, s: &mut Serializer) {
        match s.learn_cyclic(Rc::as_ptr(self) as *const c_void) {
            None => {
                s.serialize(&(0 as usize));
                s.serialize(&**self);
            }
            Some(id) => {
                s.serialize(&id);
            }
        }
    }
}
impl<'a, T: 'static + 'a + Deserialize> Deserialize for Rc<T> {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let id = d.deserialize::<usize>();
        match std::num::NonZeroUsize::new(id) {
            None => {
                let rc = Self::new(d.deserialize());
                d.learn_cyclic(rc.clone());
                rc
            }
            Some(id) => d.get_cyclic::<Rc<T>>(id).clone(),
        }
    }
}
impl<'a, T: 'static + 'a + Deserialize> DeserializeBoxed<'a> for Rc<T> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl<'a, T: 'a + Serialize> Serialize for Arc<T> {
    fn serialize_self(&self, s: &mut Serializer) {
        match s.learn_cyclic(Arc::as_ptr(self) as *const c_void) {
            None => {
                s.serialize(&(0 as usize));
                s.serialize(&**self);
            }
            Some(id) => {
                s.serialize(&id);
            }
        }
    }
}
impl<'a, T: 'static + 'a + Deserialize> Deserialize for Arc<T> {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let id = d.deserialize::<usize>();
        match std::num::NonZeroUsize::new(id) {
            None => {
                let rc = Self::new(d.deserialize());
                d.learn_cyclic(rc.clone());
                rc
            }
            Some(id) => d.get_cyclic::<Arc<T>>(id).clone(),
        }
    }
}
impl<'a, T: 'static + 'a + Deserialize> DeserializeBoxed<'a> for Arc<T> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::path::PathBuf {
    fn serialize_self(&self, s: &mut Serializer) {
        // XXX: unnecessary heap usage
        s.serialize(&self.as_os_str().to_owned());
    }
}
impl Deserialize for std::path::PathBuf {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        d.deserialize::<std::ffi::OsString>().into()
    }
}
impl<'a> DeserializeBoxed<'a> for std::path::PathBuf {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

macro_rules! impl_serialize_for_primitive {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize_self(&self, s: &mut Serializer) {
                s.write(&self.to_ne_bytes());
            }
        }
        impl Deserialize for $t {
            fn deserialize_self(d: &mut Deserializer) -> Self {
                let mut buf = [0u8; std::mem::size_of::<Self>()];
                d.read(&mut buf);
                Self::from_ne_bytes(buf)
            }
        }
        impl<'a> DeserializeBoxed<'a> for $t {
            fn deserialize_on_heap(
                &self,
                d: &mut Deserializer,
            ) -> Box<dyn DeserializeBoxed<'a> + 'a> {
                Box::new(Self::deserialize_self(d))
            }
        }
    };
}

impl_serialize_for_primitive!(i8);
impl_serialize_for_primitive!(i16);
impl_serialize_for_primitive!(i32);
impl_serialize_for_primitive!(i64);
impl_serialize_for_primitive!(i128);
impl_serialize_for_primitive!(isize);
impl_serialize_for_primitive!(u8);
impl_serialize_for_primitive!(u16);
impl_serialize_for_primitive!(u32);
impl_serialize_for_primitive!(u64);
impl_serialize_for_primitive!(u128);
impl_serialize_for_primitive!(usize);
impl_serialize_for_primitive!(f32);
impl_serialize_for_primitive!(f64);

macro_rules! impl_serialize_for_nonzero {
    ($n:ident, $t:ty) => {
        impl Serialize for std::num::$n {
            fn serialize_self(&self, s: &mut Serializer) {
                s.write(&self.get().to_ne_bytes());
            }
        }
        impl Deserialize for std::num::$n {
            fn deserialize_self(d: &mut Deserializer) -> Self {
                let mut buf = [0u8; std::mem::size_of::<Self>()];
                d.read(&mut buf);
                Self::new(<$t>::from_ne_bytes(buf)).unwrap()
            }
        }
        impl<'a> DeserializeBoxed<'a> for std::num::$n {
            fn deserialize_on_heap(
                &self,
                d: &mut Deserializer,
            ) -> Box<dyn DeserializeBoxed<'a> + 'a> {
                Box::new(Self::deserialize_self(d))
            }
        }
    };
}

impl_serialize_for_nonzero!(NonZeroI8, i8);
impl_serialize_for_nonzero!(NonZeroI16, i16);
impl_serialize_for_nonzero!(NonZeroI32, i32);
impl_serialize_for_nonzero!(NonZeroI64, i64);
impl_serialize_for_nonzero!(NonZeroI128, i128);
impl_serialize_for_nonzero!(NonZeroIsize, isize);
impl_serialize_for_nonzero!(NonZeroU8, u8);
impl_serialize_for_nonzero!(NonZeroU16, u16);
impl_serialize_for_nonzero!(NonZeroU32, u32);
impl_serialize_for_nonzero!(NonZeroU64, u64);
impl_serialize_for_nonzero!(NonZeroU128, u128);
impl_serialize_for_nonzero!(NonZeroUsize, usize);

impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn serialize_self(&self, s: &mut Serializer) {
        for item in self {
            s.serialize(item);
        }
    }
}
impl<T: Deserialize, const N: usize> Deserialize for [T; N] {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        [0; N].map(|_| d.deserialize())
    }
}
impl<'a, T: 'a + Deserialize, const N: usize> DeserializeBoxed<'a> for [T; N] {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

macro_rules! impl_serialize_for_sequence {
    (
        $ty:ident < T $(: $tbound1:ident $(+ $tbound2:ident)*)* $(, $typaram:ident : $bound1:ident $(+ $bound2:ident)*)* >,
        $seq:ident,
        $size:ident,
        $with_capacity:expr,
        $push:expr
    ) => {
        impl<T: Serialize $(+ $tbound1 $(+ $tbound2)*)* $(, $typaram: $bound1 $(+ $bound2)*,)*> Serialize
            for $ty<T $(, $typaram)*>
        {
            fn serialize_self(&self, s: &mut Serializer) {
                s.serialize(&self.len());
                for item in self.iter() {
                    s.serialize(item);
                }
            }
        }
        impl<T: Deserialize $(+ $tbound1 $(+ $tbound2)*)* $(, $typaram: $bound1 $(+ $bound2)*,)*> Deserialize
            for $ty<T $(, $typaram)*>
        {
            fn deserialize_self(d: &mut Deserializer) -> Self {
                let $size: usize = d.deserialize();
                let mut $seq = $with_capacity;
                for _ in 0..$size {
                    $push(&mut $seq, d.deserialize());
                }
                $seq
            }
        }
        impl<'serde, T: 'serde + Deserialize $(+ $tbound1 $(+ $tbound2)*)* $(, $typaram: 'serde + $bound1 $(+ $bound2)*,)*> DeserializeBoxed<'serde>
            for $ty<T $(, $typaram)*>
        {
            fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'serde> + 'serde> {
                Box::new(Self::deserialize_self(d))
            }
        }
    }
}

macro_rules! impl_serialize_for_map {
    (
        $ty:ident <
            K $(: $kbound1:ident $(+ $kbound2:ident)*)*,
            V
            $(, $typaram:ident : $bound1:ident $(+ $bound2:ident)*)*
        >,
        $size:ident,
        $with_capacity:expr
    ) => {
        impl<
            K: Serialize $(+ $kbound1 $(+ $kbound2)*)*,
            V: Serialize
            $(, $typaram: $bound1 $(+ $bound2)*,)*
        > Serialize
            for $ty<K, V $(, $typaram)*>
        {
            fn serialize_self(&self, s: &mut Serializer) {
                s.serialize(&self.len());
                for (key, value) in self.iter() {
                    s.serialize(key);
                    s.serialize(value);
                }
            }
        }
        impl<
            K: Deserialize $(+ $kbound1 $(+ $kbound2)*)*,
            V: Deserialize
            $(, $typaram: $bound1 $(+ $bound2)*,)*
        > Deserialize
            for $ty<K, V $(, $typaram)*>
        {
            fn deserialize_self(d: &mut Deserializer) -> Self {
                let $size: usize = d.deserialize();
                let mut map = $with_capacity;
                for _ in 0..$size {
                    map.insert(d.deserialize(), d.deserialize());
                }
                map
            }
        }
        impl<
            'serde,
            K: 'serde + Deserialize $(+ $kbound1 $(+ $kbound2)*)*,
            V: 'serde + Deserialize
            $(, $typaram: 'serde + $bound1 $(+ $bound2)*,)*
        > DeserializeBoxed<'serde>
            for $ty<K, V $(, $typaram)*>
        {
            fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'serde> + 'serde> {
                Box::new(Self::deserialize_self(d))
            }
        }
    }
}

impl_serialize_for_sequence!(Vec<T>, seq, size, Vec::with_capacity(size), Vec::push);
impl_serialize_for_sequence!(
    BinaryHeap<T: Ord>,
    seq,
    size,
    BinaryHeap::with_capacity(size),
    BinaryHeap::push
);
impl_serialize_for_sequence!(
    BTreeSet<T: Eq + Ord>,
    seq,
    size,
    BTreeSet::new(),
    BTreeSet::insert
);
impl_serialize_for_sequence!(
    LinkedList<T>,
    seq,
    size,
    LinkedList::new(),
    LinkedList::push_back
);
impl_serialize_for_sequence!(
    HashSet<T: Eq + Hash, S: BuildHasher + Default>,
    seq,
    size,
    HashSet::with_capacity_and_hasher(size, S::default()),
    HashSet::insert
);
impl_serialize_for_sequence!(
    VecDeque<T>,
    seq,
    size,
    VecDeque::with_capacity(size),
    VecDeque::push_back
);
impl_serialize_for_map!(BTreeMap<K: Ord, V>, size, BTreeMap::new());
impl_serialize_for_map!(HashMap<K: Eq + Hash, V, S: BuildHasher + Default>, size, HashMap::with_capacity_and_hasher(size, S::default()));

impl<T: Serialize, E: Serialize> Serialize for Result<T, E> {
    fn serialize_self(&self, s: &mut Serializer) {
        match self {
            Ok(ref ok) => {
                s.serialize(&true);
                s.serialize(ok);
            }
            Err(ref err) => {
                s.serialize(&false);
                s.serialize(err);
            }
        }
    }
}
impl<T: Deserialize, E: Deserialize> Deserialize for Result<T, E> {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        if d.deserialize::<bool>() {
            Ok(d.deserialize())
        } else {
            Err(d.deserialize())
        }
    }
}
impl<'a, T: 'a + Deserialize, E: 'a + Deserialize> DeserializeBoxed<'a> for Result<T, E> {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for OwnedFd {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for OwnedFd {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fd = d.deserialize();
        d.drain_fd(fd)
    }
}
impl<'a> DeserializeBoxed<'a> for OwnedFd {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::fs::File {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for std::fs::File {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fd: OwnedFd = d.deserialize();
        Self::from(fd)
    }
}
impl<'a> DeserializeBoxed<'a> for std::fs::File {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::os::unix::net::UnixStream {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for std::os::unix::net::UnixStream {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fd = d.deserialize();
        <Self as From<std::os::unix::io::OwnedFd>>::from(d.drain_fd(fd))
    }
}
impl<'a> DeserializeBoxed<'a> for std::os::unix::net::UnixStream {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for openat::Dir {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for openat::Dir {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fd = d.deserialize();
        unsafe { <Self as FromRawFd>::from_raw_fd(d.drain_fd(fd).into_raw_fd()) }
    }
}
impl<'a> DeserializeBoxed<'a> for openat::Dir {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for tokio::net::UnixStream {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for tokio::net::UnixStream {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        Self::from_std(d.deserialize()).expect("Failed to deserialize tokio::net::UnixStream")
    }
}
impl<'a> DeserializeBoxed<'a> for tokio::net::UnixStream {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for tokio_seqpacket::UnixSeqpacket {
    fn serialize_self(&self, s: &mut Serializer) {
        let fd = s.add_fd(self.as_raw_fd());
        s.serialize(&fd)
    }
}
impl Deserialize for tokio_seqpacket::UnixSeqpacket {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fd = d.deserialize();
        unsafe {
            Self::from_raw_fd(d.drain_fd(fd).into_raw_fd())
                .expect("Failed to deserialize tokio_seqpacket::UnixSeqpacket")
        }
    }
}
impl<'a> DeserializeBoxed<'a> for tokio_seqpacket::UnixSeqpacket {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}

impl Serialize for std::time::Duration {
    fn serialize_self(&self, s: &mut Serializer) {
        s.serialize(&self.as_secs());
        s.serialize(&self.subsec_nanos());
    }
}
impl Deserialize for std::time::Duration {
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let secs: u64 = d.deserialize();
        let nanos: u32 = d.deserialize();
        Self::new(secs, nanos)
    }
}
impl<'a> DeserializeBoxed<'a> for std::time::Duration {
    fn deserialize_on_heap(&self, d: &mut Deserializer) -> Box<dyn DeserializeBoxed<'a> + 'a> {
        Box::new(Self::deserialize_self(d))
    }
}
