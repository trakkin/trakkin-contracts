#![forbid(unsafe_code)]

mod document;
mod endpoint;
mod error;
#[cfg(feature = "fixtures")]
pub mod fixtures;
mod package;
mod selector;

pub use document::MappingDocument;
pub use endpoint::PortableEndpoint;
pub use error::MappingError;
pub use package::{
    ForgeProvenance, MappingPackage, PackageAttribution, PackageCompatibility, PackageDocument,
    PackageRequirements, PackageSignature, VerifiedPackage, validate_content_hash,
};
pub use selector::{
    CoordinateComponent, DurationValue, FiniteOrdinal, PortableSelector, Selection,
};
