use crate::{handles::OwnedHandle, Deserializer, Object, Serializer, TransmissibleObject};

pub enum Delayed<T: Object> {
    Serialized(Vec<u8>, Vec<OwnedHandle>),
    Deserialized(T),
}

impl<T: Object> Delayed<T> {
    pub fn new(value: T) -> Self {
        Self::Deserialized(value)
    }

    pub fn deserialize(self) -> T {
        match self {
            Self::Serialized(data, handles) => Deserializer::from(data, handles).deserialize(),
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
                let handles = s1
                    .drain_handles()
                    .into_iter()
                    .map(|handle| s.add_handle(handle))
                    .collect::<Vec<usize>>();
                s.serialize(&handles);
                s.serialize(&s1.into_vec());
            }
        }
    }
    fn deserialize_self(d: &mut Deserializer) -> Self {
        let handles = d
            .deserialize::<Vec<usize>>()
            .into_iter()
            .map(|handle| d.drain_handle(handle))
            .collect();
        Delayed::Serialized(d.deserialize(), handles)
    }
    fn deserialize_on_heap<'a>(&self, d: &mut Deserializer) -> Box<dyn Object + 'a>
    where
        T: 'a,
    {
        Box::new(Self::deserialize_self(d))
    }
}

impl<T: TransmissibleObject> TransmissibleObject for Delayed<T> {}
