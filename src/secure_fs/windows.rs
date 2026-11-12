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

/// Uninhabited like [`SecureRoot`]: [`SecureRoot::open_read_only`] fails.
pub struct ReadOnlyRoot(Infallible);

impl ReadOnlyRoot {
    pub fn read_file(&self, _: &str, _: usize) -> Result<Option<Vec<u8>>, StorageError> {
        match self.0 {}
    }
}

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

    pub fn open_read_only(
        _home: &Path,
        _suffix: &[&str],
    ) -> Result<Option<ReadOnlyRoot>, StorageError> {
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

    /// Uncallable: no `SecureRoot` value can exist here, so every path to a
    /// subdirectory already failed with `UnsafeState` at open. Its only
    /// caller (`source.rs`) is `cfg(unix)`, hence the allow.
    #[allow(dead_code)]
    pub(crate) fn private_subdir(&self, _: &str) -> Result<PathBuf, StorageError> {
        match self.0 {}
    }

    /// Uncallable, as [`Self::private_subdir`]; its only caller
    /// (`agent.rs`) is `cfg(unix)`.
    #[allow(dead_code)]
    pub(crate) fn clear_private_subdir(&self, _: &str) -> Result<(), StorageError> {
        match self.0 {}
    }

    pub(crate) fn read_file_sized(
        &self,
        _: &str,
        _: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        match self.0 {}
    }

    pub(crate) fn list(&self, _: &str) -> Result<Vec<(String, u64)>, StorageError> {
        match self.0 {}
    }

    pub(crate) fn remove_file(&self, _: &str) -> Result<(), StorageError> {
        match self.0 {}
    }

    pub(crate) fn remove_stale_temps(&self, _: &str) -> Result<(), StorageError> {
        match self.0 {}
    }
}

impl Staged<'_> {
    pub(crate) fn publish(self) -> Result<(), StorageError> {
        match self.0 {}
    }
}
