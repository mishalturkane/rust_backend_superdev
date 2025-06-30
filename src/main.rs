use std::{ net::SocketAddr, str::FromStr };

use axum::{ routing::post, Json, Router };
use base64::{ engine::general_purpose, Engine as _ };
use bs58;
use ed25519_dalek::{ Keypair as DalekKeypair, PublicKey, Signature, Signer, Verifier };
use serde::{ Deserialize, Serialize };
use solana_sdk::{
    pubkey::Pubkey,
    signature::{ Keypair, Signer as SolanaSigner },
    system_instruction,
};
use spl_token::instruction as token_instruction;
use tokio::net::TcpListener;

// all the routes
#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

async fn generate_keypair() -> Json<ApiResponse<serde_json::Value>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    Json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({ "pubkey": pubkey, "secret": secret })),
        error: None,
    })
}

#[derive(Deserialize)]
struct SignRequest {
    message: String,
    secret: String,
}

async fn sign_message(Json(payload): Json<SignRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let secret_bytes = bs58::decode(&payload.secret).into_vec().unwrap_or_default();
    let keypair = DalekKeypair::from_bytes(&secret_bytes);

    if let Ok(kp) = keypair {
        let signature = kp.sign(payload.message.as_bytes());
        Json(ApiResponse {
            success: true,
            data: Some(
                serde_json::json!({
                "signature": general_purpose::STANDARD.encode(signature.to_bytes()),
                "public_key": bs58::encode(kp.public.as_bytes()).into_string(),
                "message": payload.message
            })
            ),
            error: None,
        })
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid secret key".into()),
        })
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

async fn verify_message(Json(
    payload,
): Json<VerifyRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature).unwrap_or_default();
    let pubkey_bytes = bs58::decode(&payload.pubkey).into_vec().unwrap_or_default();

    if
        let (Ok(sig), Ok(pubkey)) = (
            Signature::from_bytes(&signature_bytes),
            PublicKey::from_bytes(&pubkey_bytes),
        )
    {
        let valid = pubkey.verify(payload.message.as_bytes(), &sig).is_ok();
        Json(ApiResponse {
            success: true,
            data: Some(
                serde_json::json!({
                "valid": valid,
                "message": payload.message,
                "pubkey": payload.pubkey
            })
            ),
            error: None,
        })
    } else {
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid signature or public key".into()),
        })
    }
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn create_token(Json(
    payload,
): Json<CreateTokenRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let mint = Pubkey::from_str(&payload.mint).unwrap_or_default();
    let authority = Pubkey::from_str(&payload.mint_authority).unwrap_or_default();

    if mint == Pubkey::default() || authority == Pubkey::default() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid pubkeys".into()),
        });
    }

    let ix = token_instruction
        ::initialize_mint(&spl_token::ID, &mint, &authority, None, payload.decimals)
        .unwrap();

    let accounts = ix.accounts
        .iter()
        .map(|a| {
            serde_json::json!({
            "pubkey": a.pubkey.to_string(),
            "is_signer": a.is_signer,
            "is_writable": a.is_writable
        })
        })
        .collect::<Vec<_>>();

    Json(ApiResponse {
        success: true,
        data: Some(
            serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": general_purpose::STANDARD.encode(ix.data)
        })
        ),
        error: None,
    })
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(payload): Json<MintTokenRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let mint = Pubkey::from_str(&payload.mint).unwrap_or_default();
    let dest = Pubkey::from_str(&payload.destination).unwrap_or_default();
    let auth = Pubkey::from_str(&payload.authority).unwrap_or_default();

    if mint == Pubkey::default() || dest == Pubkey::default() || auth == Pubkey::default() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid pubkeys".into()),
        });
    }

    let ix = token_instruction
        ::mint_to(&spl_token::ID, &mint, &dest, &auth, &[], payload.amount)
        .unwrap();

    let accounts = ix.accounts
        .iter()
        .map(|a| {
            serde_json::json!({
            "pubkey": a.pubkey.to_string(),
            "is_signer": a.is_signer,
            "is_writable": a.is_writable
        })
        })
        .collect::<Vec<_>>();

    Json(ApiResponse {
        success: true,
        data: Some(
            serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": general_purpose::STANDARD.encode(ix.data)
        })
        ),
        error: None,
    })
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

async fn send_sol(Json(payload): Json<SendSolRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let from = Pubkey::from_str(&payload.from).unwrap_or_default();
    let to = Pubkey::from_str(&payload.to).unwrap_or_default();

    if from == Pubkey::default() || to == Pubkey::default() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid pubkeys".into()),
        });
    }

    let ix = system_instruction::transfer(&from, &to, payload.lamports);

    Json(ApiResponse {
        success: true,
        data: Some(
            serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": ix.accounts.iter().map(|a| a.pubkey.to_string()).collect::<Vec<_>>(),
            "instruction_data": general_purpose::STANDARD.encode(ix.data)
        })
        ),
        error: None,
    })
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn send_token(Json(payload): Json<SendTokenRequest>) -> Json<ApiResponse<serde_json::Value>> {
    let mint = Pubkey::from_str(&payload.mint).unwrap_or_default();
    let destination = Pubkey::from_str(&payload.destination).unwrap_or_default();
    let owner = Pubkey::from_str(&payload.owner).unwrap_or_default();

    if mint == Pubkey::default() || destination == Pubkey::default() || owner == Pubkey::default() {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid pubkeys".into()),
        });
    }

    let ix = token_instruction
        ::transfer(&spl_token::ID, &owner, &destination, &owner, &[], payload.amount)
        .unwrap();

    let accounts = ix.accounts
        .iter()
        .map(|a| {
            serde_json::json!({
            "pubkey": a.pubkey.to_string(),
            "isSigner": a.is_signer,
        })
        })
        .collect::<Vec<_>>();

    Json(ApiResponse {
        success: true,
        data: Some(
            serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": general_purpose::STANDARD.encode(ix.data)
        })
        ),
        error: None,
    })
}