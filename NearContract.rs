// Use NEAR SDK and ed25519-dalek
use near_sdk::{env, near_bindgen, AccountId, Balance, Promise};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use near_sdk::serde::{Deserialize, Serialize};

// Payload Structure
#[derive(Deserialize, Serialize)]
pub struct TonPayload {
    action: String,
    amount: Balance,
    parameter: String,
}

// Contract structure
#[near_bindgen]
#[derive(Default)]
pub struct TonVerifierContract {
    ton_wallet_address: String, // link with a ton wallet
}

#[near_bindgen]
impl TonVerifierContract {
    /// init
    #[init]
    pub fn new(ton_wallet_address: String) -> Self {
        Self {
            ton_wallet_address,
        }
    }

    /// Verify ton proof
    pub fn verify_ton_proof(&self, message: String, signature_bytes: Vec<u8>, pub_key_bytes: Vec<u8>) -> bool {
        let public_key = PublicKey::from_bytes(&pub_key_bytes).expect("Invalid public key");
        let signature = Signature::from_bytes(&signature_bytes).expect("Invalid signature");

        // public key verification
        public_key.verify(message.as_bytes(), &signature).is_ok()
    }

    /// Handle TON proof, get payload and execute action
    pub fn process_ton_proof(&self, proof_message: String, signature_bytes: Vec<u8>, pub_key_bytes: Vec<u8>) {
        // verify
        let is_valid = self.verify_ton_proof(proof_message.clone(), signature_bytes, pub_key_bytes);

        if !is_valid {
            env::panic_str("Invalid TON proof signature");
        }

        // Read payload
        let payload: TonPayload = near_sdk::serde_json::from_str(&proof_message).expect("Invalid payload format");

        match payload.action.as_str() {
            "Transfer" => {
                self.perform_transfer(payload.amount);
            },
            "CallContract" => {
                self.call_contract_with_parameter(&payload.parameter);
            },
            _ => {
                env::panic_str("Unsupported action in payload");
            }
        }
    }

    /// transfer
    fn perform_transfer(&self, amount: Balance) {
        let recipient = env::predecessor_account_id();
        Promise::new(recipient).transfer(amount);
    }

    /// call contract
    fn call_contract_with_parameter(&self, parameter: &str) {
        env::log_str(&format!("Calling contract with parameter: {}", parameter));
    }
}
