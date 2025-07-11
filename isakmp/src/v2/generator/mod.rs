//! Implementations for the associated function [build] of various IKEv2 packet
//! types that converts high-level Rust structs into network-encoded byte arrays

mod attribute;
mod packet;
mod payload;
mod proposal;
mod security_association;
mod transform;
