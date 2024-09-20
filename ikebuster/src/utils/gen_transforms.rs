//! Generate transforms for different types of servers

use std::collections::VecDeque;

use isakmp::strum::IntoEnumIterator;
use isakmp::v1::definitions::AuthenticationMethod;
use isakmp::v1::definitions::EncryptionAlgorithm;
use isakmp::v1::definitions::GroupDescription;
use isakmp::v1::definitions::HashAlgorithm;
use isakmp::v1::generator::Transform;
use itertools::iproduct;

/// Generate all possible transforms for IKE v1
///
/// # Parameters
/// - `transform_no`: Max number of transform to put into a single message
pub fn gen_v1_transforms(transform_no: usize) -> VecDeque<Vec<Transform>> {
    let transforms = iproduct!(
        EncryptionAlgorithm::iter().filter(|x| *x as u16 != 0),
        HashAlgorithm::iter().filter(|x| *x as u16 != 0),
        AuthenticationMethod::iter().filter(|x| *x as u16 != 0),
        GroupDescription::iter().filter(|x| *x as u16 != 0),
    )
    .map(|(e, h, a, g)| Transform {
        encryption_algorithm: e,
        hash_algorithm: h,
        authentication_method: a,
        group_description: g,
        key_size: None,
    })
    .fold(Vec::new(), |mut acc, transform| {
        if transform.encryption_algorithm == EncryptionAlgorithm::AES_CBC {
            let [mut a, mut b, mut c] = [transform.clone(), transform.clone(), transform];
            a.key_size = Some(128);
            b.key_size = Some(192);
            c.key_size = Some(256);

            acc.extend([a, b, c]);
        } else {
            acc.push(transform);
        }

        acc
    });

    let mut t = VecDeque::new();

    for chunk in transforms.chunks(transform_no) {
        t.push_back(chunk.to_vec());
    }

    t
}
