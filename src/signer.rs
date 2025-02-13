#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]
use core::fmt;
use std::{cell::OnceCell, sync::Arc};

use gcloud_sdk::{
    google::cloud::kms::{
        self,
        v1::{
            key_management_service_client::KeyManagementServiceClient, AsymmetricSignRequest,
            GetPublicKeyRequest, PublicKey,
        },
    },
    tonic::{
        self,
        Request,
        // Request
    },
    GoogleApi, GoogleAuthMiddleware,
};
use solana_sdk::{
    pubkey::{self, Pubkey},
    signature::Signature,
    signer::{Signer, SignerError},
};
use thiserror::Error;

type Client = GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>;

#[derive(Clone, Debug)]
pub struct GcpKeyRingRef {
    /// The GCP project ID.
    pub google_project_id: String,
    /// The GCP location e.g. `global`.
    pub location: String,
    /// The GCP key ring name.
    pub name: String,
}

/// Reference to a GCP KeyRing.
impl GcpKeyRingRef {
    /// Create a new GCP KeyRing reference.
    pub fn new(google_project_id: &str, location: &str, name: &str) -> Self {
        Self {
            google_project_id: google_project_id.to_string(),
            location: location.to_string(),
            name: name.to_string(),
        }
    }
}

/// Identifies a specific key version in the key ring.
#[derive(Debug)]
pub struct KeySpecifier(String);

impl KeySpecifier {
    /// Construct a new specifier for a key with a given keyring, id and version.
    pub fn new(keyring: GcpKeyRingRef, key_id: &str, version: u64) -> Self {
        Self(format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            keyring.google_project_id, keyring.location, keyring.name, key_id, version,
        ))
    }
}

/// Google Cloud Platform Key Management Service (GCP KMS) solana signer.
///
/// The GCP KMS signer uses the GCP KMS service to sign transactions.
///
/// # Example
///
/// ```rust
/// use solana_sdk::signer::Signer;
/// use solana_signer_gcp::{GcpKeyRingRef, GcpSigner, KeySpecifier};
/// use gcloud_sdk::{
///     google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient, GoogleApi,
/// };
///
/// # async fn test() {
///
/// let project_id = std::env::var("GOOGLE_PROJECT_ID").expect("GOOGLE_PROJECT_ID");
/// let location = std::env::var("GOOGLE_LOCATION").expect("GOOGLE_LOCATION");
/// let keyring_name = std::env::var("GOOGLE_KEYRING").expect("GOOGLE_KEYRING");
///
/// let keyring = GcpKeyRingRef::new(&project_id, &location, &keyring_name);
/// let client = GoogleApi::from_function(
///     KeyManagementServiceClient::new,
///     "https://cloudkms.googleapis.com",
///     None,
/// )
/// .await
/// .expect("Failed to create GCP KMS Client");
///
/// let key_name = "...";
/// let key_version = 1;
/// let key_specifier = KeySpecifier::new(keyring, key_name, key_version);
/// let signer = GcpSigner::new(client, key_specifier).await.unwrap();
///
/// println!("{:?}",signer.pubkey());
///
/// }
/// ```
#[derive(Clone)]
pub struct GcpSigner {
    client: Client,
    key_name: String,
    pubkey: Arc<OnceCell<Pubkey>>,
    address: String,
}

impl fmt::Debug for GcpSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpSigner")
            .field("key_name", &self.key_name)
            .field("address", &self.address)
            .finish()
    }
}

/// Errors thrown by [`GcpSigner`].
#[derive(Debug, Error)]
pub enum GcpSignerError {
    #[error(transparent)]
    GoogleKmsError(#[from] gcloud_sdk::error::Error),

    #[error(transparent)]
    RequestError(#[from] tonic::Status),

    #[error(transparent)]
    PemError(#[from] pem::PemError),

    #[error("Invalid pubkey length {0}")]
    InvalidPubkeyLength(usize),
}

impl Into<SignerError> for GcpSignerError {
    fn into(self) -> SignerError {
        SignerError::Custom(self.to_string())
    }
}

impl Signer for GcpSigner {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self
            .pubkey
            .get()
            .copied()
            .ok_or(SignerError::Custom("Cannot get pubkey".to_string()))?)
    }

    #[tokio::main]
    async fn try_sign_message(
        &self,
        message: &[u8],
    ) -> Result<solana_sdk::signature::Signature, SignerError> {
        request_sign_data(&self.client, &self.key_name, message)
            .await
            .and_then(decode_signature)
            .map_err(Into::into)
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl GcpSigner {
    pub async fn new(client: Client, key_specifier: KeySpecifier) -> Result<Self, GcpSignerError> {
        let key_name = key_specifier.0;
        let pubkey = request_get_pubkey(&client, &key_name).await?;

        Ok(Self {
            client,
            key_name,
            pubkey: Arc::new(OnceCell::from(from_public_key_pem(pubkey)?)),
            address: String::from(""),
        })
    }

    pub async fn get_pubkey(&self) -> Result<PublicKey, GcpSignerError> {
        request_get_pubkey(&self.client, &self.key_name).await
    }
}

#[instrument(skip(client), err)]
async fn request_get_pubkey(
    client: &Client,
    kms_key_name: &str,
) -> Result<PublicKey, GcpSignerError> {
    let mut request = tonic::Request::new(GetPublicKeyRequest {
        name: kms_key_name.to_string(),
    });
    request.metadata_mut().insert(
        "x-goog-request-params",
        format!("name={}", &kms_key_name).parse().unwrap(),
    );

    client
        .get()
        .get_public_key(request)
        .await
        .map(|r| r.into_inner())
        .map_err(Into::into)
}

#[instrument(skip(client, data), fields(data = %hex::encode(data)), err)]
async fn request_sign_data(
    client: &Client,
    kms_key_name: &str,
    data: &[u8],
) -> Result<Vec<u8>, GcpSignerError> {
    let mut request = Request::new(AsymmetricSignRequest {
        name: kms_key_name.to_string(),
        data: data.to_vec(),
        ..Default::default()
    });

    request.metadata_mut().insert(
        "x-goog-request-params",
        format!("name={}", kms_key_name).parse().unwrap(),
    );

    let response = client.get().asymmetric_sign(request).await?;
    let signature = response.into_inner().signature;
    Ok(signature)
}

#[instrument(err)]
fn from_public_key_pem(key: PublicKey) -> Result<Pubkey, GcpSignerError> {
    let pkey = pem::parse(key.pem)?;

    let content = pkey.contents();

    let mut array = [0u8; 32];

    match content.len() {
        32 => {
            array.copy_from_slice(content);
            Ok(Pubkey::new_from_array(array))
        }
        44 => {
            array.copy_from_slice(&content[12..]);
            Ok(Pubkey::new_from_array(array))
        }
        size => Err(GcpSignerError::InvalidPubkeyLength(size)),
    }
}

fn decode_signature(raw: Vec<u8>) -> Result<Signature, GcpSignerError> {
    let mut bytes = [0; 64];
    bytes.copy_from_slice(&raw);
    Ok(Signature::from(bytes))
}

#[cfg(test)]
mod test {
    use solana_sdk::signer::Signer;

    use super::*;
    // use gcloud_sdk::google::cloud::kms::v1::PublicKey;

    const KEY_NAME: &str = "projects/naturalselectionlabs/locations/us/keyRings/solana/cryptoKeys/solana/cryptoKeyVersions/1";

    #[tokio::test]
    async fn test_request_get_pubkey() {
        let client = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await
        .unwrap();
        let key_name = KEY_NAME;
        let resp = request_get_pubkey(&client, key_name).await.unwrap();

        assert_eq!(resp.pem, String::from("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHDvdzUyFFG3pdn0ldkbPD81WliidLKqBHxfAt/3FbkU=\n-----END PUBLIC KEY-----\n"));
        assert_eq!(resp.name, key_name);
    }

    #[tokio::test]
    async fn test_request_sign_digest() {
        let client = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await
        .unwrap();
        let key_name = KEY_NAME;

        let data = b"hello world";
        let resp = request_sign_data(&client, key_name, data).await.unwrap();
        let except = [
            181, 191, 109, 41, 160, 193, 142, 180, 189, 128, 75, 238, 225, 137, 205, 105, 79, 163,
            62, 20, 237, 215, 64, 66, 91, 153, 117, 133, 236, 192, 160, 253, 101, 158, 128, 115,
            50, 181, 118, 60, 192, 247, 130, 182, 177, 15, 203, 109, 23, 152, 36, 158, 131, 118,
            193, 70, 153, 188, 209, 196, 229, 0, 103, 5,
        ];
        assert_eq!(resp, except);
    }

    #[tokio::test]
    async fn test_sol_pubkey() {
        let client = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await
        .unwrap();
        let key_name = "projects/naturalselectionlabs/locations/us/keyRings/solana/cryptoKeys/solana/cryptoKeyVersions/1";
        let signer = GcpSigner::new(client, KeySpecifier(String::from(key_name)))
            .await
            .unwrap();
        assert_eq!(
            signer.pubkey(),
            Pubkey::from_str_const("2uDMykU9nKeSUg2JLPktsMNYyrUmv7y9EpLHn847H7Zn")
        );
    }

    #[test]
    fn test_key_specifier() {
        let keyring = GcpKeyRingRef::new("test", "global", "test");
        let key_specifier = KeySpecifier::new(keyring, "test", 1);
        assert_eq!(
            key_specifier.0,
            "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
        );
    }

    #[test]
    fn test_gcp_keyring_ref() {
        let keyring = GcpKeyRingRef::new("test", "global", "test");
        assert_eq!(keyring.google_project_id, "test");
        assert_eq!(keyring.location, "global");
        assert_eq!(keyring.name, "test");
    }

    #[test]
    fn test_public_key_pem() {
        let pem_str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHDvdzUyFFG3pdn0ldkbPD81WliidLKqBHxfAt/3FbkU=\n-----END PUBLIC KEY-----\n";
        let pkey = pem::parse(pem_str).unwrap();
        let content = pkey.contents();
        let mut array = [0u8; 32];
        array.copy_from_slice(&content[12..]);
        let pubkey = Pubkey::new_from_array(array);
        assert_eq!(
            pubkey,
            Pubkey::from_str_const("2uDMykU9nKeSUg2JLPktsMNYyrUmv7y9EpLHn847H7Zn")
        );
    }
}
