use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web::error::ErrorBadRequest;
use solana_sdk::{native_token::LAMPORTS_PER_SOL, pubkey::Pubkey, signature::{Keypair, Signer}};
use solana_client::rpc_client::RpcClient;
use serde::Deserialize;
use tokio::task;
use serde_json::json;
use bs58;
use std::str::FromStr;
use spl_token::instruction as token_instruction;
use base64::{Engine as _, engine::general_purpose};
use spl_associated_token_account;

struct Statename{
    app_name: String
}

#[derive(Deserialize)]
struct Airdrop{
    to: String
}

#[derive(Deserialize)]
struct Info{
    pubkey: String
}

#[derive(Deserialize)]
struct CreateToken {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintToken {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessage {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessage {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSol {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendToken {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

fn json_error_handler(_err: actix_web::error::JsonPayloadError, _req: &actix_web::HttpRequest) -> actix_web::Error {
    ErrorBadRequest(json!({
        "success": false,
        "error": "Invalid JSON format or missing required fields"
    }))
}



#[post("/keypair")]
async fn keypair() -> impl Responder{
    let key = Keypair::new();
    let public_key = key.pubkey().to_string();
    let secret_key_base58 = bs58::encode(&key.to_bytes()).into_string();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
          "pubkey": public_key,
          "secret": secret_key_base58
        }
    }))
}



#[get("/")]
async fn hello() -> impl Responder{
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "message": "hello world"
        }
    }))
}

#[post("/airdrop")]
async fn airdrops(test: web::Json<Airdrop>) -> impl Responder{
    let to = &test.to;
    const RPC_URL: &str = "https://api.devnet.solana.com";
    let publickey = match Pubkey::from_str(&to) {
        Ok(key) => key,
        Err(_e) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid pubkey"
        }))
    };
    let client = RpcClient::new(RPC_URL);   
    let transaction = task::spawn_blocking(move || {
        client.request_airdrop(&publickey, 2*LAMPORTS_PER_SOL)
    }).await.unwrap();
    match transaction {
         Ok(signature) => HttpResponse::Ok().json(json!({
             "success": true,
             "data": {
                 "signature": signature.to_string()
             }
         })),
         Err(_err) => HttpResponse::BadRequest().json(json!({
             "success": false,
             "error": "Airdrop failed"
         }))
     }
}

#[post("/token/create")]
async fn create_token(req: web::Json<CreateToken>) -> impl Responder {
    let mint_authority_pubkey = match Pubkey::from_str(&req.mintAuthority) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid mint authority pubkey"
        })),
    };

    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid mint pubkey"
        })),
    };

    if req.decimals > 9 {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Decimals must be between 0 and 9"
        }));
    }
    let initialize_mint_ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None, 
        req.decimals,
    ).unwrap();
    let accounts: Vec<serde_json::Value> = initialize_mint_ix.accounts.iter().map(|account| {
        json!({
            "pubkey": account.pubkey.to_string(),
            "is_signer": account.is_signer,
            "is_writable": account.is_writable
        })
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(&initialize_mint_ix.data);

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "program_id": initialize_mint_ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}

#[post("/token/mint")]
async fn mint_token(req: web::Json<MintToken>) -> impl Responder {
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid mint pubkey"
        })),
    };

    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid destination pubkey"
        })),
    };

    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid authority pubkey"
        })),
    };
    let mint_to_ix = match token_instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[], 
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("Failed to create mint instruction: {}", e)
        })),
    };
    let accounts: Vec<serde_json::Value> = mint_to_ix.accounts.iter().map(|account| {
        json!({
            "pubkey": account.pubkey.to_string(),
            "is_signer": account.is_signer,
            "is_writable": account.is_writable
        })
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(&mint_to_ix.data);

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "program_id": mint_to_ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}

#[post("/message/sign")]
async fn sign_message(req: web::Json<SignMessage>) -> impl Responder {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => {
            if bytes.len() != 64 {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "error": "Invalid secret key length"
                }));
            }
            bytes
        },
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid base58 secret key"
        })),
    };
    let keypairs = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid secret key format"
        })),
    };

    // Sign the message
    let message_bytes = req.message.as_bytes();
    let signature = keypairs.sign_message(message_bytes);
    
    // Encode signature as base64
    let signature_base64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key = keypairs.pubkey().to_string();

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "signature": signature_base64,
            "public_key": public_key,
            "message": req.message
        }
    }))
}

#[post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessage>) -> impl Responder {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid public key"
        })),
    };
    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => {
            if bytes.len() != 64 {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "error": "Invalid signature length"
                }));
            }
            bytes
        },
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid base64 signature"
        })),
    };
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid signature format"
        })),
    };
    let message_bytes = req.message.as_bytes();
    let is_valid = signature.verify(pubkey.as_ref(), message_bytes);

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "valid": is_valid,
            "message": req.message,
            "pubkey": req.pubkey
        }
    }))
}

#[post("/send/sol")]
async fn send_sol(req: web::Json<SendSol>) -> impl Responder {
    if req.from.is_empty() || req.to.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }
    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid from address"
        })),
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid to address"
        })),
    };
    let transfer_ix = solana_program::system_instruction::transfer(
        &from_pubkey,
        &to_pubkey,
        req.lamports,
    );

    let accounts: Vec<String> = transfer_ix.accounts.iter().map(|account| {
        account.pubkey.to_string()
    }).collect();
    
    let instruction_data = general_purpose::STANDARD.encode(&transfer_ix.data);

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "program_id": transfer_ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}

#[post("/send/token")]
async fn send_token(req: web::Json<SendToken>) -> impl Responder {

    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Missing required fields"
        }));
    }
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Amount must be greater than 0"
        }));
    }
    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid destination address"
        })),
    };
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid mint address"
        })),
    };
    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(key) => key,
        Err(_) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": "Invalid owner address"
        })),
    };
    let source_ata = spl_associated_token_account::get_associated_token_address(
        &owner_pubkey,
        &mint_pubkey,
    );
    let transfer_ix = match token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_pubkey,
        &owner_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("Failed to create transfer instruction: {}", e)
        })),
    };
    let accounts: Vec<serde_json::Value> = transfer_ix.accounts.iter().map(|account| {
        json!({
            "pubkey": account.pubkey.to_string(),
            "isSigner": account.is_signer
        })
    }).collect();
    let instruction_data = general_purpose::STANDARD.encode(&transfer_ix.data);

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "program_id": transfer_ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        }
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .app_data(web::JsonConfig::default().error_handler(json_error_handler))
            .app_data(web::Data::new(Statename{app_name:String::from("test")}))
            .service(hello)
            .service(airdrops)
            .service(keypair)
            .service(create_token)
            .service(mint_token)
            .service(sign_message)
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    }).bind(("0.0.0.0", 8080))?.run().await
}
