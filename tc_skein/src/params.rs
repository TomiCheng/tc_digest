//! Ready-made Skein parameter types.

#[cfg(feature = "alloc")]
mod skein_params_owned;
mod skein_params_ref;

#[cfg(feature = "alloc")]
pub use skein_params_owned::SkeinParamsOwned;
pub use skein_params_ref::SkeinParamsRef;
