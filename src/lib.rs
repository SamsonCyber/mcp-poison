//! mcpdoctor: protocol-native MCP tool-surface auditor.
//!
//! Default path is non-mutating: connect (or load a captured `tools/list`),
//! walk every schema string leaf, emit structured findings, optional pin/check.

pub mod client;
pub mod detectors;
pub mod hash;
pub mod normalize;
pub mod pin;
pub mod report;
pub mod scan;
pub mod types;

pub use report::ScanReport;
pub use scan::{scan_from_tools_list, scan_multi_lists, scan_stdio, ScanOptions};
pub use types::{Finding, ProofClass, Severity};
