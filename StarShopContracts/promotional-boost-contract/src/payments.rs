use stellar_sdk::{
    transaction::TransactionBuilder,
    asset::Asset,
    types::IntoAmount,
    types::{PublicKey, SecretKey},
    network::Network,
    operations::{Operation, PaymentOperation},
    Server,
};

use std::str::FromStr;

pub struct PaymentManager {
    server: Server,
    network: Network,
    sender_secret: SecretKey,
}

impl PaymentManager {
    pub fn new(secret: &str) -> Self {
        let sender_secret = SecretKey::from_encoding(secret).expect("Invalid secret key");
        let network = Network::new_test();
        let server = Server::new("https://horizon-testnet.stellar.org").unwrap();

        Self {
            server,
            network,
            sender_secret,
        }
    }

    pub async fn process_payment(&self, destination: &str, xlm_amount: &str) -> Result<(), String> {
        let destination_pk = PublicKey::from_account_id(destination)
            .map_err(|e| format!("Invalid destination: {}", e))?;

        let source_account = self
            .server
            .load_account(&self.sender_secret.public_key())
            .await
            .map_err(|e| format!("Failed to load source account: {}", e))?;

        let payment_op = Operation::new_payment(PaymentOperation::new(
            destination_pk.clone(),
            (xlm_amount.parse::<f64>().unwrap() * 10_000_000.0) as i64, // 1 XLM = 10^7 stroops
        ));

        let tx = TransactionBuilder::new(source_account, self.network.clone())
            .add_operation(payment_op)
            .build()
            .map_err(|e| format!("Failed to build transaction: {}", e))?
            .sign(&self.sender_secret);

        self.server
            .submit_transaction(&tx)
            .await
            .map_err(|e| format!("Payment failed: {:?}", e))?;

        Ok(())
    }
}
