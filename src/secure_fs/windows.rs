//! Fail-closed stub for every platform without a secure implementation,
//! Windows included until `SA-2B1b`.
//!
//! `SecureRoot` wraps an uninhabited type, so no value of it can exist: every
//! open returns [`StorageError::UnsafeState`], and with no root there is no
//! state to read, write, authorize against or serve.

use std::{convert::Infallible, marker::PhantomData, path::Path, path::PathBuf};

use super::StorageError;

pub struct SecureRoot(Infallible);

pub(crate) struct Staged<'a>(Infallible, PhantomData<&'a ()>);

pub fn trusted_home() -> Result<PathBuf, StorageError> {
    Err(StorageError::UnsafeState)
}

pub fn default_root_path() -> Result<PathBuf, StorageError> {
    Err(StorageError::UnsafeState)
}

impl SecureRoot {
    pub fn open_default() -> Result<Self, StorageError> {
        Err(StorageError::UnsafeState)
    }

    pub fn open_under(_home: &Path, _suffix: &[&str]) -> Result<Self, StorageError> {
        Err(StorageError::UnsafeState)
    }

    pub(crate) fn read_file(&self, _: &str, _: usize) -> Result<Option<Vec<u8>>, StorageError> {
        match self.0 {}
    }

    pub(crate) fn stage(&self, _: &str, _: &[u8]) -> Result<Staged<'_>, StorageError> {
        match self.0 {}
    }

    pub(crate) fn remove_stale_temp(&self, _: &str) -> Result<(), StorageError> {
        match self.0 {}
    }
}

impl Staged<'_> {
    pub(crate) fn publish(self) -> Result<(), StorageError> {
        match self.0 {}
    }
}
