use crossmist::{Deserializer, Object, Serializer};
use std::io::Result;
use std::ops::Deref;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::os::unix::io::{AsRawFd, FromRawFd};

pub struct OpenAtDir(openat::Dir);

impl OpenAtDir {
    pub fn open<P: openat::AsPath>(path: P) -> Result<Self> {
        Ok(Self(openat::Dir::open(path)?))
    }

    pub fn sub_dir<P: openat::AsPath>(&self, path: P) -> Result<Self> {
        Ok(Self(self.0.sub_dir(path)?))
    }

    pub fn try_clone(&self) -> Result<Self> {
        // Built-in try_clone erroneously does not set CLOEXEC
        let fd = nix::fcntl::fcntl(self.0.as_raw_fd(), nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0))?;
        Ok(Self(unsafe { openat::Dir::from_raw_fd(fd) }))
    }
}

impl Deref for OpenAtDir {
    type Target = openat::Dir;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Object for OpenAtDir {
    fn serialize_self(&self, s: &mut Serializer) {
        let handle = s.add_handle(self.0.as_raw_fd());
        s.serialize(&handle)
    }
    fn deserialize_self(d: &mut Deserializer) -> Self {
        Self(unsafe { openat::Dir::from_raw_fd(d.deserialize::<OwnedFd>().into_raw_fd()) })
    }
    fn deserialize_on_heap<'a>(&self, d: &mut Deserializer) -> Box<dyn Object + 'a>
    where
        Self: 'a,
    {
        Box::new(Self::deserialize_self(d))
    }
}
