use rustix::process::{Gid, Uid};

// Not mapping external uid 0 to anything ensures it's impossible to do anything real root can from
// inside the sandbox

// Sandboxed root:
// The external UID, i.e. same uid all files in the image are owned by
pub const EXTERNAL_ROOT_UID: Uid = Uid::from_raw_unchecked(1);
pub const INTERNAL_ROOT_UID: Uid = Uid::from_raw_unchecked(0);

// Sandboxed user:
// The external UID, which we use upon creating files and pipes
pub const EXTERNAL_USER_UID: Uid = Uid::from_raw_unchecked(2);
// The UID the sandboxed program sees
pub const INTERNAL_USER_UID: Uid = Uid::from_raw_unchecked(1000);

pub const NOBODY_UID: Uid = Uid::from_raw_unchecked(65534);

// The GIDs, inferred in the same way
pub const EXTERNAL_ROOT_GID: Gid = Gid::from_raw_unchecked(1);
pub const INTERNAL_ROOT_GID: Gid = Gid::from_raw_unchecked(0);

pub const EXTERNAL_USER_GID: Gid = Gid::from_raw_unchecked(2);
pub const INTERNAL_USER_GID: Gid = Gid::from_raw_unchecked(1000);

pub const NOGRP_GID: Gid = Gid::from_raw_unchecked(65534);
