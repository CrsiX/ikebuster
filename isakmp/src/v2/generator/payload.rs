use crate::v2::definitions::params::PayloadType;
use crate::v2::definitions::Payload;

impl Payload {
    pub(crate) fn build(&self, next_payload: PayloadType) -> Vec<u8> {
        vec![]
    }
}
