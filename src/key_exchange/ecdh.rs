use rand::OsRng;
use num_traits::Zero;
use num_bigint::BigInt;

use utils::{ montgomery_ladder, comb_method };
use utils::ecc::{ ECPKeypair };
use utils::ecc_curves::{ ECPGroup, ECPPoint, ECPSupportedCurves, ECPCurveShape };

pub struct ECDH {
    pub group: ECPGroup,
    pub q: ECPPoint,                // our public value (public key) 
    pub z: BigInt,                  // shared secret
    pub peer_q: Option<ECPPoint>,   // peer's public value (public key)
    keypair: ECPKeypair             // Generated keypair, for reference (private value stored here)
}

impl ECDH {

    /// Elliptic curve Diffie-Hellman. This is a Rust implementation of 
    /// the TLS ECDH source code, written in C, found here:
    /// https://github.com/ARMmbed/mbedtls/blob/master/library/ecdh.c
    /// 
    /// ### Arguments
    /// 
    /// * `curve` - Curve group to use
    pub fn new(curve: ECPSupportedCurves) -> Self {
        let zero = BigInt::zero();
        let mut rng = OsRng::new().unwrap();
        let keypair = ECPKeypair::new(curve).setup(&mut rng);

        ECDH {
            group: keypair.group.clone(),
            q: keypair.q.clone(),
            peer_q: None,
            z: zero.clone(),
            keypair: keypair
        }
    }

    /// Derive and export the shared secret
    /// 
    /// ### Arguments
    /// 
    /// * `rng` - Random number generator
    pub fn generate_shared_key(&mut self, mut rng: &mut OsRng) -> BigInt {
        // Check peer Q point first
        self.check_peer_q();

        let curve_shape = self.group.get_curve_shape();

        let P = match curve_shape {
            ECPCurveShape::Montgomery => {
                montgomery_ladder::multiply(&self.keypair.group, &self.keypair.d, &self.peer_q.clone().unwrap())
            },
            ECPCurveShape::ShortWeierstrass => {
                comb_method::multiply(&mut self.keypair.group, &self.keypair.d, &self.peer_q.clone().unwrap(), &mut rng)
            }
        };

        self.z = P.x.clone();
        P.x
    }

    /// Checks that a peer's Q point is available and valid
    fn check_peer_q(&self) -> () {
        if self.peer_q.is_none() {
            panic!("No peer point available to generate shared secret for");
        }

        let validity_check = self.keypair.check_public_key(&self.peer_q.clone().unwrap());

        if !validity_check.0 {
            panic!(validity_check.1);
        }
    }

}

/*----- TESTS -----*/

#[cfg(test)]
mod ecdh_test {

    use rand::OsRng;
    use cryptopunk::key_exchange::ecdh::ECDH;
    use utils::ecc_curves::ECPSupportedCurves;

    #[test]
    fn successful_shared_secret_weierstrass() {
        let mut rng = OsRng::new().unwrap();

        let mut dh = ECDH::new(ECPSupportedCurves::BP256R1);
        let self_q = dh.q.clone();

        let mut dh2 = ECDH::new(ECPSupportedCurves::BP256R1);
        let peer_q = dh2.q.clone();

        dh.peer_q = Some(peer_q);
        dh2.peer_q = Some(self_q);

        let check_from_first = dh.generate_shared_key(&mut rng);
        let check_from_second = dh2.generate_shared_key(&mut rng);

        assert_eq!(check_from_first, check_from_second);
    }
    
    #[test]
    fn successful_shared_secret_montgomery() {
        let mut rng = OsRng::new().unwrap();

        let mut dh = ECDH::new(ECPSupportedCurves::Curve25519);
        let self_q = dh.q.clone();

        let mut dh2 = ECDH::new(ECPSupportedCurves::Curve25519);
        let peer_q = dh2.q.clone();

        dh.peer_q = Some(peer_q);
        dh2.peer_q = Some(self_q);

        let check_from_first = dh.generate_shared_key(&mut rng);
        let check_from_second = dh2.generate_shared_key(&mut rng);

        assert_eq!(check_from_first, check_from_second);
    }
}