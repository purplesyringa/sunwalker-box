use crate::{Deserializer, Object, Serializer};
use std::os::unix::io::OwnedFd;

pub enum Delayed<T: Object> {
    Serialized(Vec<u8>, Vec<OwnedFd>),
    Deserialized(T),
}

impl<T: Object> Delayed<T> {
    pub fn new(value: T) -> Self {
        Self::Deserialized(value)
    }

    pub fn deserialize(self) -> T {
        match self {
            Self::Serialized(data, fds) => Deserializer::from(data, fds).deserialize(),
            Self::Deserialized(_) => panic!("Cannot deserialize a deserialized Delayed value"),
        }
    }
}

impl<T: Object> Object for Delayed<T> {
    fn serialize_self(&self, s: &mut Serializer) {
        match self {
            Self::Serialized(_, _) => panic!("Cannot serialize a serialized Delayed value"),
            Self::Deserialized(value) => {
                let mut s1 = Serializer::new();
                s1.serialize(value);
                let fds = s1
                    .drain_fds()
                    .into_iter()
                    .map(|fd| s.add_fd(fd))
                    .collect::<Vec<usize>>();
                s.serialize(&fds);
                s.serialize(&s1.into_vec());
            }
        }
    }
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let fds = d
            .deserialize::<Vec<usize>>()
            .into_iter()
            .map(|fd| d.drain_fd(fd))
            .collect();
        Delayed::Serialized(d.deserialize(), fds)
    }
    fn deserialize_on_heap<'a>(&self, d: &mut Deserializer) -> Box<dyn Object + 'a> where T: 'a {
        Box::new(Self::deserialize_self(d))
    }
}
