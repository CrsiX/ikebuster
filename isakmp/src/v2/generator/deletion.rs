use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::Deletion;

impl Deletion {
    pub fn build(&self, next_payload: PayloadType) -> Vec<u8> {
        // TODO
        vec![]
    }
}
