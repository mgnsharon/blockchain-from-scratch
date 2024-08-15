//! We now have a hash-linked header chain that accepts simple extrinsics and tracks simple state.
//! Now we will explore consensus. We are not looking at finality or fork choice here. Rather,
//! we are adding validity rules. There are two common types of validity rules and we will explore
//! both.
//! 1. Rules to throttle authoring. In this case we will use a simple PoW.
//! 2. Arbitrary / Political rules. Here we will implement two alternate validity rules
use crate::hash;
use rand::{thread_rng, Rng};

// We will use Rust's built-in hashing where the output type is u64. I'll make an alias
// so the code is slightly more readable.
type Hash = u64;

/// In this lesson we are introducing proof of work onto our blocks. We need a hash threshold.
/// You may change this as you see fit, and I encourage you to experiment. Probably best to start
/// high so we aren't wasting time mining. I'll start with 1 in 100 blocks being valid.
const THRESHOLD: u64 = u64::max_value() / 100;

/// In this lesson we introduce the concept of a contentious hard fork. The fork will happen at
/// this block height.
const FORK_HEIGHT: u64 = 2;

/// The header is now expanded to contain a consensus digest.
/// For Proof of Work, the consensus digest is basically just a nonce which gets the block
/// hash below a certain threshold. Although we could call the field `nonce` we will leave
/// the more general `digest` term. For PoA we would have a cryptographic signature in this field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
	parent: Hash,
	height: u64,
	extrinsic: u64,
	state: u64,
	consensus_digest: u64,
}

// Here are the methods for creating new header and verifying headers.
// It is your job to write them.
impl Header {
	/// Returns a new valid genesis header.
	fn genesis() -> Self {
		Header { parent: 0, height: 0, extrinsic: 0, state: 0, consensus_digest: 0 }
	}

	/// Create and return a valid child header.
	fn child(&self, extrinsic: u64) -> Self {
		let mut rng = thread_rng();
		let consensus_digest: u64 = rng.gen();

		let h = Header {
			parent: hash(self),
			height: self.height + 1,
			extrinsic,
			state: self.state + extrinsic,
			consensus_digest,
		};

		if hash(&h) < THRESHOLD {
			h
		} else {
			self.child(extrinsic)
		}
	}

	/// Verify that all the given headers form a valid chain from this header to the tip.
	///
	/// In addition to all the rules we had before, we now need to check that the block hash
	/// is below a specific threshold.
	fn verify_sub_chain(&self, chain: &[Header]) -> bool {
		let chain_iter = chain.iter();
		let mut prev = self.clone();
		for block in chain_iter {
			if !verify_block(VerificationMethod::Threshold(block, &prev)) {
				return false;
			}
			prev = block.clone();
		}
		true
	}

	// After the blockchain ran for a while, a political rift formed in the community.
	// (See the constant FORK_HEIGHT) which is set to 2 by default.
	// Most community members have become obsessed over the state of the blockchain.
	// On the one side, people believe that only blocks with even states should be valid.
	// On the other side, people believe in only blocks with odd states.

	/// verify that the given headers form a valid chain.
	/// In this case "valid" means that the STATE MUST BE EVEN.
	fn verify_sub_chain_even(&self, chain: &[Header]) -> bool {
		let chain_iter = chain.iter();
		let mut prev = self.clone();
		for block in chain_iter {
			if block.height > FORK_HEIGHT {
				if !verify_block(VerificationMethod::Even(block, &prev)) {
					return false;
				}
			} else if !verify_block(VerificationMethod::Threshold(block, &prev)) {
				return false;
			}
			prev = block.clone();
		}
		true
	}

	/// verify that the given headers form a valid chain.
	/// In this case "valid" means that the STATE MUST BE ODD.
	fn verify_sub_chain_odd(&self, chain: &[Header]) -> bool {
		let chain_iter = chain.iter();
		let mut prev = self.clone();
		for block in chain_iter {
			if block.height > FORK_HEIGHT {
				if !verify_block(VerificationMethod::Odd(block, &prev)) {
					return false;
				}
			} else if !verify_block(VerificationMethod::Threshold(block, &prev)) {
				return false;
			}
			prev = block.clone();
		}
		true
	}
}

fn is_block_valid(block: &Header, prev: &Header) -> bool {
	block.height == prev.height + 1
		&& block.state == prev.state + block.extrinsic
		&& block.parent == hash(&prev)
		&& hash(&block) < THRESHOLD
}

fn verify_block(method: VerificationMethod) -> bool {
	match method {
		VerificationMethod::Threshold(block, prev) => is_block_valid(block, prev),
		VerificationMethod::Even(block, prev) => {
			is_block_valid(block, prev) && block.state % 2 == 0
		},
		VerificationMethod::Odd(block, prev) => is_block_valid(block, prev) && block.state % 2 != 0,
	}
}

enum VerificationMethod<'a> {
	Threshold(&'a Header, &'a Header),
	Even(&'a Header, &'a Header),
	Odd(&'a Header, &'a Header),
}
/// Build and return two different chains with a common prefix.
/// They should have the same genesis header.
///
/// Both chains should be valid according to the original validity rules.
/// The first chain should be valid only according to the even rules.
/// The second chain should be valid only according to the odd rules.
///
/// Return your solutions as three vectors:
/// 1. The common prefix including genesis
/// 2. The even suffix (non-overlapping with the common prefix)
/// 3. The odd suffix (non-overlapping with the common prefix)
///
/// Here is an example of two such chains:
///            /-- 3 -- 4
/// G -- 1 -- 2
///            \-- 3'-- 4'
fn build_contentious_forked_chain() -> (Vec<Header>, Vec<Header>, Vec<Header>) {
	let g = Header::genesis();
	let a1 = g.child(2); // 2
	let a2 = a1.child(5); // 7
	let e1 = a2.child(1); // 8
	let e2 = e1.child(2); // 10
	let o1 = a2.child(2); // 9
	let o2 = o1.child(4); // 13

	(vec![g, a1, a2], vec![e1, e2], vec![o1, o2])
}

// To run these tests: `cargo test bc_3`
#[test]
fn bc_3_genesis_block_height() {
	let g = Header::genesis();
	assert!(g.height == 0);
}

#[test]
fn bc_3_genesis_block_parent() {
	let g = Header::genesis();
	assert!(g.parent == 0);
}

#[test]
fn bc_3_genesis_block_extrinsic() {
	// Typically genesis blocks do not have any extrinsics.
	// In Substrate they never do. So our convention is to have the extrinsic be 0.
	let g = Header::genesis();
	assert!(g.extrinsic == 0);
}

#[test]
fn bc_3_genesis_block_state() {
	let g = Header::genesis();
	assert!(g.state == 0);
}

#[test]
fn bc_3_genesis_consensus_digest() {
	// We could require that the genesis block have a valid proof of work as well.
	// But instead I've chosen the simpler path of defining the nonce = 0 in genesis.
	let g = Header::genesis();
	let b1 = g.child(7); // <- no way of knowing what consensus_digest is yet
	assert!(hash(&b1) < THRESHOLD); // Original
	                            // assert!(hash(&b1.consensus_digest) < THRESHOLD);
}

#[test]
fn bc_3_child_block_height() {
	let g = Header::genesis();
	let b1 = g.child(0);
	assert!(b1.height == 1);
}

#[test]
fn bc_3_child_block_parent() {
	let g = Header::genesis();
	let b1 = g.child(0);
	assert!(b1.parent == hash(&g));
}

#[test]
fn bc_3_child_block_extrinsic() {
	let g = Header::genesis();
	let b1 = g.child(7);
	assert_eq!(b1.extrinsic, 7);
}

#[test]
fn bc_3_child_block_state() {
	let g = Header::genesis();
	let b1 = g.child(7);
	assert_eq!(b1.state, 7);
}

#[test]
fn bc_3_child_block_consensus_digest() {
	let g = Header::genesis();
	let b1 = g.child(7);
	assert!(hash(&b1) < THRESHOLD);
}

#[test]
fn bc_3_verify_genesis_only() {
	let g = Header::genesis();

	assert!(g.verify_sub_chain(&[]));
}

#[test]
fn bc_3_verify_three_blocks() {
	let g = Header::genesis();
	let b1 = g.child(5);
	let b2 = b1.child(6);

	assert_eq!(b2.state, 11);
	assert!(g.verify_sub_chain(&[b1, b2]));
}

#[test]
fn bc_3_cant_verify_invalid_parent() {
	let g = Header::genesis();
	let mut b1 = g.child(5);
	b1.parent = 10;

	assert!(!g.verify_sub_chain(&[b1]));
}

#[test]
fn bc_3_cant_verify_invalid_number() {
	let g = Header::genesis();
	let mut b1 = g.child(5);
	b1.height = 10;

	assert!(!g.verify_sub_chain(&[b1]));
}

#[test]
fn bc_3_cant_verify_invalid_state() {
	let g = Header::genesis();
	let mut b1 = g.child(5);
	b1.state = 10;

	assert!(!g.verify_sub_chain(&[b1]));
}

#[test]
fn bc_3_cant_verify_invalid_pow() {
	let g = Header::genesis();
	let mut b1 = g.child(5);
	// It is possible that this test will pass with a false positive because
	// the PoW difficulty is relatively low.
	b1.consensus_digest = 10;

	assert!(!g.verify_sub_chain(&[b1]));
}

#[test]
fn bc_3_even_chain_valid() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
					  // It' all about the states, not the extrinsics. So once the state is even
					  // we need to keep it that way. So add evens
	let b3 = b2.child(1); // 4
	let b4 = b3.child(2); // 6

	assert!(g.verify_sub_chain_even(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_even_chain_invalid_first_block_after_fork() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
	let b3 = b2.child(2); // 5 - invalid
	let b4 = b3.child(1); // 6

	assert!(!g.verify_sub_chain_even(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_even_chain_invalid_second_block_after_fork() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
	let b3 = b2.child(1); // 4
	let b4 = b3.child(1); // 5 - invalid

	assert!(!g.verify_sub_chain_even(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_odd_chain_valid() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
					  // It' all about the states, not the extrinsics. So once the state is odd
					  // we need to keep it that way. So add evens
	let b3 = b2.child(2); // 5
	let b4 = b3.child(2); // 7

	assert!(g.verify_sub_chain_odd(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_odd_chain_invalid_first_block_after_fork() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
	let b3 = b2.child(1); // 4 - invalid
	let b4 = b3.child(1); // 5

	assert!(!g.verify_sub_chain_odd(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_odd_chain_invalid_second_block_after_fork() {
	let g = Header::genesis(); // 0
	let b1 = g.child(2); // 2
	let b2 = b1.child(1); // 3
	let b3 = b2.child(2); // 5
	let b4 = b3.child(1); // 6 - invalid

	assert!(!g.verify_sub_chain_odd(&[b1, b2, b3, b4]));
}

#[test]
fn bc_3_verify_forked_chain() {
	let (prefix, even, odd) = build_contentious_forked_chain();

	let g = &prefix[0];
	let full_even_chain = [&prefix[1..], &even].concat();
	let full_odd_chain = [&prefix[1..], &odd].concat();

	// Both chains are individually valid according to the original rules.
	assert!(g.verify_sub_chain(&full_even_chain[..]));
	assert!(g.verify_sub_chain(&full_odd_chain[..]));

	// Only the even chain is valid according to the even rules
	assert!(g.verify_sub_chain_even(&full_even_chain[..]));
	assert!(!g.verify_sub_chain_even(&full_odd_chain[..]));

	// Only the odd chain is valid according to the odd rules
	assert!(!g.verify_sub_chain_odd(&full_even_chain[..]));
	assert!(g.verify_sub_chain_odd(&full_odd_chain[..]));
}
