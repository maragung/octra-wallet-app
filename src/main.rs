#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::seq::SliceRandom;
use rand::RngCore;
use ed25519_dalek::{Signer, SigningKey, Verifier}; 
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Digest, Sha512};
use hmac::{Hmac, Mac};
use bip39::Mnemonic; 
use std::process::Command;

const WALLETS_DIR: &str = "wallets";
const MY_WALLET_FILE: &str = "MyWallet.txt";
const LOG_FILE: &str = "logs.txt";
const SETTINGS_FILE: &str = "settings.json";
const DEFAULT_RPC_URL: &str = "https://octra.network";

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletData {
    #[serde(rename = "priv")] 
    priv_key: String, 
    addr: String,
    #[serde(default)]
    rpc: String,
}

#[derive(Clone, Debug)]
struct WalletState {
    filename: String,
    address: String,
    private_key: String,
    balance: f64,
    nonce: u64,
    rpc_url: String,
}

#[derive(Debug, Clone)]
struct GeneratedWallet {
    mnemonic: String,
    private_key_b64: String,
    public_key_b64: String,
    address: String,
    filename_suggestion: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AppSettings {
    theme: String,
    zoom: f32,
    default_rpc: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "Dark".to_string(),
            zoom: 1.0,
            default_rpc: DEFAULT_RPC_URL.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum AppAction {
    RefreshBalance { idx: usize, rpc: String },
    CheckAllBalances { rpc_override: Option<String> },
    CheckTargetBalance { addr: String, rpc: String },
    SendTx {
        wallet_idx: usize,
        to: String,
        amount: f64,
        is_sweep: bool,
        rpc: String,
    },
    StartBatch {
        mode: BatchMode,
        start_idx: usize,
        count: usize,
        target_addr: Option<String>,
        target_amount: Option<f64>,
        rpc_override: Option<String>,
    },
    ReloadWallets,
}

#[derive(Debug, Clone, PartialEq)]
enum BatchMode {
    SendSpecific,
    SweepToTarget,
    SweepToRandom,
}

#[derive(Debug, Clone)]
enum AppEvent {
    Log(String, String),
    BalanceUpdated(usize, f64, u64),
    TargetBalanceChecked(String, f64, u64),
    WalletProcessing(usize),
    TxResult(usize, bool, String, String),
    BatchProgress(usize, usize),
    BatchFinished,
    WalletsReloaded(Vec<WalletState>),
    StoppedAt(String, String),
}

#[derive(PartialEq, Clone, Copy)]
enum SortColumn {
    Filename,
    Address,
    Balance,
}

fn generate_entropy() -> [u8; 16] {
    let mut entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}

fn derive_master_key(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut mac = HmacSha512::new_from_slice(b"Octra seed").expect("HMAC error");
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let (key, chain) = result.split_at(32);
    (key.to_vec(), chain.to_vec())
}

fn derive_child_key(private_key: &[u8], chain_code: &[u8], index: u32) -> (Vec<u8>, Vec<u8>) {
    let mut data = Vec::new();
    
    if index >= 0x80000000 {
        data.push(0x00);
        data.extend_from_slice(private_key);
        data.extend_from_slice(&index.to_be_bytes());
    } else {
        let key_bytes: [u8; 32] = private_key.try_into().expect("Invalid key len");
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        data.extend_from_slice(verifying_key.as_bytes());
        data.extend_from_slice(&index.to_be_bytes());
    }

    let mut mac = HmacSha512::new_from_slice(chain_code).expect("HMAC error");
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let (key, chain) = result.split_at(32);
    (key.to_vec(), chain.to_vec())
}

fn create_octra_address(pub_key: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(pub_key);
    let hash = hasher.finalize();
    let base58 = bs58::encode(hash).into_string();
    format!("oct{}", base58)
}

fn generate_new_wallet_logic() -> GeneratedWallet {
    let entropy = generate_entropy();
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
    let seed = mnemonic.to_seed("");
    
    let (mut key, mut chain) = derive_master_key(&seed);

    let path = [
        0x80000000 + 345, 0x80000000 + 0, 0x80000000 + 0, 0x80000000 + 0, 
        0x80000000 + 0,   0x80000000 + 0, 0x80000000 + 0, 0
    ];

    for index in path {
        let (k, c) = derive_child_key(&key, &chain, index);
        key = k;
        chain = c;
    }

    let key_bytes: [u8; 32] = key.try_into().expect("Invalid key len");
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();

    let priv_b64 = BASE64.encode(signing_key.to_bytes());
    let pub_b64 = BASE64.encode(verifying_key.to_bytes());
    let address = create_octra_address(verifying_key.as_bytes());

    let suffix = &address[address.len().saturating_sub(8)..];
    let filename = format!("wallet_{}.json", suffix);

    GeneratedWallet {
        mnemonic: mnemonic.words().collect::<Vec<&str>>().join(" "),
        private_key_b64: priv_b64,
        public_key_b64: pub_b64,
        address,
        filename_suggestion: filename,
    }
}

fn verify_key_pair(priv_b64: &str, pub_b64: &str, address: &str) -> bool {
    let Ok(priv_bytes) = BASE64.decode(priv_b64) else { return false; };
    let Ok(pub_bytes) = BASE64.decode(pub_b64) else { return false; };
    let Ok(key_bytes) = priv_bytes.try_into() else { return false; };
    
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    
    if verifying_key.as_bytes() != pub_bytes.as_slice() { return false; }
    
    let derived_address = create_octra_address(verifying_key.as_bytes());
    if derived_address != address { return false; }

    let message = b"Octra Wallet Verification";
    let signature = signing_key.sign(message);
    
    verifying_key.verify(message, &signature).is_ok()
}

async fn fetch_balance(rpc: &str, addr: &str) -> anyhow::Result<(f64, u64)> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?;
    let url_bal = format!("{}/balance/{}", rpc, addr);
    let resp_bal: serde_json::Value = client.get(&url_bal).send().await?.json().await?;
    
    let url_stage = format!("{}/staging", rpc);
    let resp_stage_req = client.get(&url_stage).send().await;
    let resp_stage: serde_json::Value = match resp_stage_req {
        Ok(resp) => resp.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({})
    };

    let balance = resp_bal["balance"].as_f64().unwrap_or(0.0);
    let mut nonce = resp_bal["nonce"].as_u64().unwrap_or(0);

    if let Some(txs) = resp_stage["staged_transactions"].as_array() {
        let pending_nonce = txs.iter()
            .filter(|tx| tx["from"].as_str().unwrap_or("") == addr)
            .map(|tx| tx["nonce"].as_u64().unwrap_or(0))
            .max();
        if let Some(pn) = pending_nonce {
            if pn >= nonce { nonce = pn; }
        }
    }
    Ok((balance, nonce))
}

fn create_signed_tx(priv_key_b64: &str, from: &str, to: &str, amount: f64, nonce: u64) -> anyhow::Result<(serde_json::Value, String)> {
    let priv_bytes = BASE64.decode(priv_key_b64).map_err(|_| anyhow::anyhow!("Invalid Key"))?;
    let key_bytes: [u8; 32] = priv_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid len"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    let pub_key_b64 = BASE64.encode(verifying_key.to_bytes());

    let amount_micro = (amount * 1_000_000.0) as u64;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();

    let mut tx_map = serde_json::Map::new();
    tx_map.insert("from".to_string(), serde_json::json!(from));
    tx_map.insert("to_".to_string(), serde_json::json!(to));
    tx_map.insert("amount".to_string(), serde_json::json!(amount_micro.to_string()));
    tx_map.insert("nonce".to_string(), serde_json::json!(nonce));
    tx_map.insert("ou".to_string(), serde_json::json!("30000"));
    tx_map.insert("timestamp".to_string(), serde_json::json!(timestamp));

    let tx_string = serde_json::to_string(&tx_map)?;
    let signature = signing_key.sign(tx_string.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    tx_map.insert("signature".to_string(), serde_json::json!(sig_b64));
    tx_map.insert("public_key".to_string(), serde_json::json!(pub_key_b64));

    let hash = sha2::Sha256::digest(tx_string.as_bytes());
    Ok((serde_json::Value::Object(tx_map), hex::encode(hash)))
}

async fn send_transaction(rpc: &str, tx_json: serde_json::Value) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{}/send-tx", rpc);
    let resp = client.post(&url).json(&tx_json).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if status.is_success() && text.contains("accepted") { Ok(text) } 
    else { Err(anyhow::anyhow!("Error {}: {}", status, text)) }
}

fn natural_sort_key(s: &str) -> Vec<(bool, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut is_digit = false;

    for c in s.chars() {
        if c.is_ascii_digit() {
            if !is_digit && !current.is_empty() {
                parts.push((false, current.clone()));
                current.clear();
            }
            is_digit = true;
        } else {
            if is_digit && !current.is_empty() {
                parts.push((true, current.clone()));
                current.clear();
            }
            is_digit = false;
        }
        current.push(c);
    }
    parts.push((is_digit, current));
    parts
}

fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ka = natural_sort_key(a);
    let kb = natural_sort_key(b);
    
    for (ia, ib) in ka.iter().zip(kb.iter()) {
        if ia.0 != ib.0 { return ia.0.cmp(&ib.0); }
        if ia.0 {
            if let (Ok(na), Ok(nb)) = (ia.1.parse::<u64>(), ib.1.parse::<u64>()) {
                 let cmp = na.cmp(&nb);
                 if cmp != std::cmp::Ordering::Equal { return cmp; }
            } else {
                 if ia.1.len() != ib.1.len() { return ia.1.len().cmp(&ib.1.len()); }
                 let cmp = ia.1.cmp(&ib.1);
                 if cmp != std::cmp::Ordering::Equal { return cmp; }
            }
        } else {
            let cmp = ia.1.cmp(&ib.1);
            if cmp != std::cmp::Ordering::Equal { return cmp; }
        }
    }
    ka.len().cmp(&kb.len())
}

fn load_wallets_from_disk(target_dir: &Path) -> Vec<WalletState> {
    let mut loaded_wallets = Vec::new();
    if let Ok(entries) = fs::read_dir(target_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(data) = serde_json::from_str::<WalletData>(&content) {
                        loaded_wallets.push(WalletState {
                            filename: path.file_name().unwrap().to_string_lossy().to_string(),
                            address: data.addr,
                            private_key: data.priv_key,
                            balance: 0.0,
                            nonce: 0,
                            rpc_url: if data.rpc.is_empty() { DEFAULT_RPC_URL.to_string() } else { data.rpc },
                        });
                    }
                }
            }
        }
    }
    loaded_wallets.sort_by(|a, b| natural_cmp(&a.filename, &b.filename));
    loaded_wallets
}

fn load_settings() -> AppSettings {
    if let Ok(content) = fs::read_to_string(SETTINGS_FILE) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        AppSettings::default()
    }
}

fn save_settings(settings: &AppSettings) {
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = fs::write(SETTINGS_FILE, json);
    }
}

struct WalletApp {
    wallets: Vec<WalletState>,
    selected_wallet_idx: usize,
    input_to_address: String,
    input_amount: String,
    batch_mode: BatchMode,
    batch_count: usize,
    batch_start_idx: usize,
    batch_input_addr: String,
    batch_input_amt: String,
    is_batch_running: bool,
    batch_progress: f32,
    tx_sender: Sender<AppAction>,
    rx_receiver: Receiver<AppEvent>,
    logs: VecDeque<String>,
    search_path: String,
    wallets_dir_path: PathBuf,
    settings: AppSettings,
    show_generator: bool,
    show_about: bool,
    show_balance_checker: bool,
    generated_wallet: Option<GeneratedWallet>,
    verify_status: String,
    save_status_msg: String,
    gen_show_mnemonic: bool,
    gen_show_privkey: bool,
    balance_filter: String,
    sort_col: SortColumn,
    sort_desc: bool,
    clipboard: Option<arboard::Clipboard>,
    
    show_target_info: bool,
    target_info_data: Option<(String, f64, u64)>,
    
    processing_idx: Option<usize>,
    use_default_rpc: bool,
    stop_signal: Arc<AtomicBool>,
}

impl WalletApp {
    fn new(cc: &eframe::CreationContext) -> Self {
        let (action_tx, action_rx) = channel::<AppAction>();
        let (event_tx, event_rx) = channel::<AppEvent>();
        let settings = load_settings();

        if settings.theme == "Light" {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
        } else {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
        }

        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
        let target_dir = exe_dir.join(WALLETS_DIR);
        
        if !target_dir.exists() { let _ = fs::create_dir_all(&target_dir); }

        let search_path_display = target_dir.canonicalize().unwrap_or_else(|_| target_dir.clone()).display().to_string();
        let initial_wallets = load_wallets_from_disk(&target_dir);
        let wallets_dir_clone = target_dir.clone();
        
        let stop_signal = Arc::new(AtomicBool::new(false));
        let thread_stop_signal = stop_signal.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut current_wallets_in_thread = initial_wallets.clone();
            rt.block_on(async move {
                while let Ok(action) = action_rx.recv() {
                    match action {
                        AppAction::ReloadWallets => {
                            current_wallets_in_thread = load_wallets_from_disk(&wallets_dir_clone);
                            let _ = event_tx.send(AppEvent::WalletsReloaded(current_wallets_in_thread.clone()));
                            let _ = event_tx.send(AppEvent::Log("INFO".into(), format!("Reloaded {} wallets", current_wallets_in_thread.len())));
                        }
                        AppAction::CheckAllBalances { rpc_override } => {
                            let total = current_wallets_in_thread.len();
                            for (i, w) in current_wallets_in_thread.iter().enumerate() {
                                if thread_stop_signal.load(Ordering::Relaxed) {
                                    let _ = event_tx.send(AppEvent::StoppedAt(w.filename.clone(), w.address.clone()));
                                    break;
                                }
                                let _ = event_tx.send(AppEvent::WalletProcessing(i));
                                let rpc = rpc_override.clone().unwrap_or(w.rpc_url.clone());
                                match fetch_balance(&rpc, &w.address).await {
                                    Ok((bal, nonce)) => { let _ = event_tx.send(AppEvent::BalanceUpdated(i, bal, nonce)); }
                                    Err(_) => {}
                                }
                                if i % 10 == 0 { let _ = event_tx.send(AppEvent::BatchProgress(i, total)); }
                            }
                            let _ = event_tx.send(AppEvent::BatchFinished);
                        }
                        AppAction::CheckTargetBalance { addr, rpc } => {
                            match fetch_balance(&rpc, &addr).await {
                                Ok((bal, nonce)) => { let _ = event_tx.send(AppEvent::TargetBalanceChecked(addr, bal, nonce)); },
                                Err(e) => { let _ = event_tx.send(AppEvent::Log("ERROR".into(), format!("Target check fail: {}", e))); }
                            }
                        }
                        AppAction::RefreshBalance { idx, rpc } => {
                            if idx < current_wallets_in_thread.len() {
                                let w = &current_wallets_in_thread[idx];
                                match fetch_balance(&rpc, &w.address).await {
                                    Ok((bal, nonce)) => { let _ = event_tx.send(AppEvent::BalanceUpdated(idx, bal, nonce)); }
                                    Err(e) => { let _ = event_tx.send(AppEvent::Log("ERROR".to_string(), format!("Check bal fail: {}", e))); }
                                }
                            }
                        }
                        AppAction::SendTx { wallet_idx, to, amount, is_sweep, rpc } => {
                            if wallet_idx < current_wallets_in_thread.len() {
                                let w = &current_wallets_in_thread[wallet_idx];
                                let mut final_amt = amount;
                                let mut final_nonce = 0;
                                let res = async {
                                    let (bal, nonce) = fetch_balance(&rpc, &w.address).await?;
                                    final_nonce = nonce;
                                    if is_sweep { final_amt = bal - 0.001; }
                                    if final_amt <= 0.0 { return Err(anyhow::anyhow!("Low Balance: {}", bal)); }
                                    let (tx, hash) = create_signed_tx(&w.private_key, &w.address, &to, final_amt, nonce + 1)?;
                                    let msg = send_transaction(&rpc, tx).await?;
                                    Ok((hash, msg, bal - final_amt, nonce + 1))
                                }.await;

                                match res {
                                    Ok((hash, msg, new_bal, new_nonce)) => {
                                        let _ = event_tx.send(AppEvent::TxResult(wallet_idx, true, hash, msg));
                                        let _ = event_tx.send(AppEvent::BalanceUpdated(wallet_idx, new_bal, new_nonce));
                                    },
                                    Err(e) => {
                                        let _ = event_tx.send(AppEvent::TxResult(wallet_idx, false, "Fail".into(), e.to_string()));
                                    }
                                }
                            }
                        }
                        AppAction::StartBatch { mode, start_idx, count, target_addr, target_amount, rpc_override } => {
                            let end = (start_idx + count).min(current_wallets_in_thread.len());
                            let total = end - start_idx;
                            let mut processed = 0;

                            for i in start_idx..end {
                                if thread_stop_signal.load(Ordering::Relaxed) {
                                    if i < current_wallets_in_thread.len() {
                                        let w = &current_wallets_in_thread[i];
                                        let _ = event_tx.send(AppEvent::StoppedAt(w.filename.clone(), w.address.clone()));
                                    }
                                    break;
                                }

                                let _ = event_tx.send(AppEvent::BatchProgress(processed, total));
                                processed += 1;
                                let w = &current_wallets_in_thread[i];
                                let rpc = rpc_override.clone().unwrap_or(w.rpc_url.clone());
                                
                                let (bal, nonce) = match fetch_balance(&rpc, &w.address).await {
                                    Ok(res) => res,
                                    Err(_) => (0.0, 0),
                                };

                                let mut final_to = target_addr.clone().unwrap_or_default();
                                let mut final_amt = target_amount.unwrap_or(0.0);
                                let mut should_send = true;

                                match mode {
                                    BatchMode::SendSpecific => {},
                                    BatchMode::SweepToTarget => { final_amt = bal - 0.001; },
                                    BatchMode::SweepToRandom => {
                                        if let Ok(content) = fs::read_to_string(MY_WALLET_FILE) {
                                            let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
                                            if let Some(addr) = lines.choose(&mut rand::thread_rng()) {
                                                final_to = addr.to_string();
                                                final_amt = bal - 0.001;
                                            } else { should_send = false; }
                                        } else { should_send = false; }
                                    }
                                }

                                if should_send && final_amt > 0.0 && !final_to.is_empty() {
                                    match create_signed_tx(&w.private_key, &w.address, &final_to, final_amt, nonce + 1) {
                                        Ok((tx_json, tx_hash)) => {
                                            match send_transaction(&rpc, tx_json).await {
                                                Ok(msg) => { let _ = event_tx.send(AppEvent::TxResult(i, true, tx_hash, msg)); },
                                                Err(e) => { let _ = event_tx.send(AppEvent::TxResult(i, false, "Send Fail".into(), e.to_string())); }
                                            }
                                        },
                                        Err(_) => {}
                                    }
                                } else {
                                    let _ = event_tx.send(AppEvent::Log("SKIP".into(), format!("Wallet {} skipped", w.filename)));
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            let _ = event_tx.send(AppEvent::BatchFinished);
                        }
                    }
                }
            });
        });

        let ui_wallets = load_wallets_from_disk(&target_dir);
        let clipboard = arboard::Clipboard::new().ok();

        Self {
            wallets: ui_wallets,
            selected_wallet_idx: 0,
            input_to_address: String::new(),
            input_amount: "0.0".to_string(),
            batch_mode: BatchMode::SendSpecific,
            batch_count: 10,
            batch_start_idx: 0,
            batch_input_addr: String::new(),
            batch_input_amt: "0.0".to_string(),
            is_batch_running: false,
            batch_progress: 0.0,
            tx_sender: action_tx,
            rx_receiver: event_rx,
            logs: VecDeque::new(),
            search_path: search_path_display,
            wallets_dir_path: target_dir,
            settings,
            show_generator: false,
            show_about: false,
            show_balance_checker: false,
            generated_wallet: None,
            verify_status: String::new(),
            save_status_msg: String::new(),
            gen_show_mnemonic: false,
            gen_show_privkey: false,
            balance_filter: String::new(),
            sort_col: SortColumn::Filename,
            sort_desc: false,
            clipboard,
            show_target_info: false,
            target_info_data: None,
            processing_idx: None,
            use_default_rpc: false,
            stop_signal,
        }
    }

    fn get_rpc(&self, w: &WalletState) -> String {
        if self.use_default_rpc {
            self.settings.default_rpc.clone()
        } else {
            w.rpc_url.clone()
        }
    }

    fn get_rpc_override(&self) -> Option<String> {
        if self.use_default_rpc {
            Some(self.settings.default_rpc.clone())
        } else {
            None
        }
    }

    fn add_log(&mut self, level: &str, msg: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        self.logs.push_front(format!("[{}] {} | {}", timestamp, level, msg));
        if self.logs.len() > 200 { self.logs.pop_back(); }
    }

    fn apply_settings(&mut self, ctx: &egui::Context) {
        ctx.set_pixels_per_point(self.settings.zoom);
        if self.settings.theme == "Dark" {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }
    }
}

impl eframe::App for WalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_pixels_per_point(self.settings.zoom);

        while let Ok(event) = self.rx_receiver.try_recv() {
            match event {
                AppEvent::WalletsReloaded(new_list) => self.wallets = new_list,
                AppEvent::WalletProcessing(idx) => self.processing_idx = Some(idx),
                AppEvent::BalanceUpdated(idx, bal, nonce) => {
                    if idx < self.wallets.len() {
                        self.wallets[idx].balance = bal;
                        self.wallets[idx].nonce = nonce;
                    }
                }
                AppEvent::TargetBalanceChecked(addr, bal, nonce) => {
                    self.target_info_data = Some((addr, bal, nonce));
                    self.show_target_info = true;
                }
                AppEvent::Log(lvl, msg) => self.add_log(&lvl, &msg),
                AppEvent::TxResult(idx, success, hash, msg) => {
                    let w_name = self.wallets.get(idx).map(|w| w.filename.clone()).unwrap_or("?".into());
                    let status = if success { "SUCCESS" } else { "FAILED" };
                    self.add_log(status, &format!("[{}] Hash: {} | Msg: {}", w_name, hash, msg));
                }
                AppEvent::BatchProgress(curr, total) => self.batch_progress = if total > 0 { curr as f32 / total as f32 } else { 0.0 },
                AppEvent::BatchFinished => {
                    self.is_batch_running = false;
                    self.processing_idx = None;
                    self.batch_progress = 1.0;
                    self.add_log("INFO", "Operation Completed");
                }
                AppEvent::StoppedAt(file, addr) => {
                    self.is_batch_running = false;
                    self.processing_idx = None;
                    self.add_log("STOP", &format!("Stopped at File: {}, Addr: {}", file, addr));
                    println!("Stopped at File: {}, Addr: {}", file, addr);
                }
            }
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Menu", |ui| {
                    if ui.button("➕ Create / Generate Wallet").clicked() {
                        self.show_generator = true;
                        ui.close_menu();
                    }
                    if ui.button("🔄 Reload Wallets").clicked() {
                        let _ = self.tx_sender.send(AppAction::ReloadWallets);
                        ui.close_menu();
                    }
                });

                ui.menu_button("Tools", |ui| {
                    if ui.button("💰 Check All Balances").clicked() {
                        self.show_balance_checker = true;
                        ui.close_menu();
                    }
                    if ui.button("📂 Open MyWallet.txt").clicked() {
                        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
                        let dir = exe_path.parent().unwrap_or(Path::new("."));
                        let file_path = dir.join(MY_WALLET_FILE);
                        if !file_path.exists() { let _ = fs::write(&file_path, ""); }
                        if cfg!(target_os = "windows") {
                            Command::new("cmd").args(["/C", "start", MY_WALLET_FILE]).current_dir(dir).spawn().ok();
                        } else if cfg!(target_os = "macos") {
                            Command::new("open").arg(MY_WALLET_FILE).current_dir(dir).spawn().ok();
                        } else {
                            Command::new("xdg-open").arg(MY_WALLET_FILE).current_dir(dir).spawn().ok();
                        }
                        ui.close_menu();
                    }
                });

                ui.menu_button("Config", |ui| {
                    ui.label("Theme:");
                    let is_dark = self.settings.theme == "Dark";
                    if ui.button(if is_dark { "☀ Light" } else { "🌙 Dark" }).clicked() {
                        self.settings.theme = if is_dark { "Light".into() } else { "Dark".into() };
                        self.apply_settings(ctx);
                        save_settings(&self.settings);
                    }
                    ui.separator();
                    ui.label("Default RPC:");
                    if ui.text_edit_singleline(&mut self.settings.default_rpc).changed() {
                        save_settings(&self.settings);
                    }
                    ui.separator();
                    ui.label("Zoom:");
                    if ui.add(egui::Slider::new(&mut self.settings.zoom, 0.8..=2.0)).changed() {
                        save_settings(&self.settings); 
                        ctx.request_repaint();
                    }
                    if ui.button("Reset Zoom").clicked() {
                         self.settings.zoom = 1.0;
                         save_settings(&self.settings);
                    }
                });

                if ui.button("About").clicked() {
                    self.show_about = true;
                }
            });
        });

        if self.show_about {
            let mut open = true;
            egui::Window::new("About")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Maragung by Gemini AI");
                });
            self.show_about = open;
        }

        if self.show_target_info {
            let mut open = true;
            egui::Window::new("Target Address Info")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    if let Some((addr, bal, nonce)) = &self.target_info_data {
                        ui.label(format!("Address: {}", addr));
                        ui.label(format!("Balance: {:.6} OCT", bal));
                        ui.label(format!("Nonce: {}", nonce));
                    }
                });
            self.show_target_info = open;
        }

        if self.show_balance_checker {
            let mut open = true;
            egui::Window::new("Balance Checker & Tools")
                .open(&mut open)
                .default_width(700.0)
                .default_height(500.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!self.is_batch_running, egui::Button::new("🔄 Check All Balances")).clicked() {
                            self.stop_signal.store(false, Ordering::Relaxed);
                            self.is_batch_running = true;
                            let _ = self.tx_sender.send(AppAction::CheckAllBalances { rpc_override: self.get_rpc_override() });
                        }
                        if self.is_batch_running {
                            if ui.add(egui::Button::new("🛑 STOP").fill(egui::Color32::RED)).clicked() {
                                self.stop_signal.store(true, Ordering::Relaxed);
                            }
                        }
                        ui.separator();
                        ui.label("Filter:");
                        ui.text_edit_singleline(&mut self.balance_filter);
                    });
                    ui.add_space(5.0);

                    let mut display_indices: Vec<usize> = self.wallets.iter().enumerate()
                        .filter(|(_, w)| {
                            if self.balance_filter.is_empty() { return true; }
                            let q = self.balance_filter.to_lowercase();
                            w.filename.to_lowercase().contains(&q) || 
                            w.address.to_lowercase().contains(&q) ||
                            format!("{}", w.balance).contains(&q)
                        })
                        .map(|(i, _)| i)
                        .collect();

                    display_indices.sort_by(|&a, &b| {
                        let wa = &self.wallets[a];
                        let wb = &self.wallets[b];
                        let cmp = match self.sort_col {
                            SortColumn::Filename => natural_cmp(&wa.filename, &wb.filename),
                            SortColumn::Address => wa.address.cmp(&wb.address),
                            SortColumn::Balance => wa.balance.partial_cmp(&wb.balance).unwrap_or(std::cmp::Ordering::Equal),
                        };
                        if self.sort_desc { cmp.reverse() } else { cmp }
                    });

                    ui.horizontal(|ui| {
                        if ui.button("📂 Export Filenames (.txt)").clicked() {
                            if let Some(path) = rfd::FileDialog::new().set_file_name("filenames.txt").save_file() {
                                let content = display_indices.iter().map(|&i| self.wallets[i].filename.clone()).collect::<Vec<_>>().join("\n");
                                let _ = fs::write(path, content);
                            }
                        }
                        if ui.button("📋 Export Address List (.txt)").clicked() {
                            if let Some(path) = rfd::FileDialog::new().set_file_name("addresses.txt").save_file() {
                                let content = display_indices.iter().map(|&i| self.wallets[i].address.clone()).collect::<Vec<_>>().join("\n");
                                let _ = fs::write(path, content);
                            }
                        }
                    });
                    ui.separator();

                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("bal_grid").striped(true).min_col_width(100.0).show(ui, |ui| {
                            if ui.button("Filename ↕").clicked() {
                                if self.sort_col == SortColumn::Filename { self.sort_desc = !self.sort_desc; }
                                else { self.sort_col = SortColumn::Filename; self.sort_desc = false; }
                            }
                            if ui.button("Address ↕").clicked() {
                                if self.sort_col == SortColumn::Address { self.sort_desc = !self.sort_desc; }
                                else { self.sort_col = SortColumn::Address; self.sort_desc = false; }
                            }
                            if ui.button("Balance (OCT) ↕").clicked() {
                                if self.sort_col == SortColumn::Balance { self.sort_desc = !self.sort_desc; }
                                else { self.sort_col = SortColumn::Balance; self.sort_desc = true; }
                            }
                            ui.end_row();

                            for &idx in &display_indices {
                                let w = &self.wallets[idx];
                                let color = if Some(idx) == self.processing_idx { egui::Color32::BLUE } else { ui.style().visuals.text_color() };
                                
                                ui.colored_label(color, &w.filename);
                                ui.colored_label(color, &w.address);
                                ui.colored_label(color, format!("{:.6}", w.balance));
                                ui.end_row();
                            }
                        });
                    });
                });
            self.show_balance_checker = open;
        }

        if self.show_generator {
            let mut open = true;
            egui::Window::new("Wallet Generator")
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(600.0)
                .show(ctx, |ui| {
                    ui.heading("Generate Octra Wallet");
                    ui.add_space(10.0);

                    if ui.button("🎲 Generate Random Wallet").clicked() {
                        self.generated_wallet = Some(generate_new_wallet_logic());
                        self.verify_status.clear();
                        self.save_status_msg.clear();
                        self.gen_show_mnemonic = false;
                        self.gen_show_privkey = false;
                    }

                    if let Some(w) = &mut self.generated_wallet {
                        ui.separator();
                        ui.heading("Result");
                        
                        ui.label("Address:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut w.address).desired_width(ui.available_width() - 40.0));
                            if ui.button("📋").on_hover_text("Copy").clicked() {
                                ui.output_mut(|o| o.copied_text = w.address.clone());
                            }
                        });
                        
                        ui.label("Mnemonic:");
                        ui.horizontal(|ui| {
                            let text_edit = egui::TextEdit::multiline(&mut w.mnemonic)
                                .password(!self.gen_show_mnemonic)
                                .desired_width(ui.available_width() - 40.0);
                            ui.add(text_edit);
                            if ui.button(if self.gen_show_mnemonic { "👁" } else { "🔒" }).clicked() {
                                self.gen_show_mnemonic = !self.gen_show_mnemonic;
                            }
                        });
                        
                        ui.label("PrivKey (B64):");
                        ui.horizontal(|ui| {
                            let text_edit = egui::TextEdit::singleline(&mut w.private_key_b64)
                                .password(!self.gen_show_privkey)
                                .desired_width(ui.available_width() - 40.0);
                            ui.add(text_edit);
                            if ui.button(if self.gen_show_privkey { "👁" } else { "🔒" }).clicked() {
                                self.gen_show_privkey = !self.gen_show_privkey;
                            }
                        });

                        ui.add_space(10.0);
                        
                        if ui.button("🔍 Verify Signature & Keys").clicked() {
                            let valid = verify_key_pair(&w.private_key_b64, &w.public_key_b64, &w.address);
                            self.verify_status = if valid { "✅ Keys Valid & Signature Verified".to_string() } else { "❌ Validation Failed".to_string() };
                        }
                        if !self.verify_status.is_empty() {
                            let color = if self.verify_status.contains("✅") { egui::Color32::GREEN } else { egui::Color32::RED };
                            ui.colored_label(color, &self.verify_status);
                        }

                        ui.add_space(10.0);
                        ui.separator();
                        ui.heading("Save Options");
                        ui.horizontal(|ui| {
                            if ui.button(format!("💾 Save to '{}'", WALLETS_DIR)).clicked() {
                                let data = WalletData {
                                    priv_key: w.private_key_b64.clone(),
                                    addr: w.address.clone(),
                                    rpc: DEFAULT_RPC_URL.to_string(),
                                };
                                let path = self.wallets_dir_path.join(&w.filename_suggestion);
                                match serde_json::to_string_pretty(&data) {
                                    Ok(json) => match fs::write(&path, json) {
                                        Ok(_) => {
                                            self.save_status_msg = format!("Saved to {:?}", path);
                                            let _ = self.tx_sender.send(AppAction::ReloadWallets);
                                        }
                                        Err(e) => self.save_status_msg = format!("File Error: {}", e),
                                    },
                                    Err(e) => self.save_status_msg = format!("JSON Error: {}", e),
                                }
                            }

                            if ui.button("📂 Save As...").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .set_file_name(&w.filename_suggestion)
                                    .save_file()
                                {
                                    let data = WalletData {
                                        priv_key: w.private_key_b64.clone(),
                                        addr: w.address.clone(),
                                        rpc: DEFAULT_RPC_URL.to_string(),
                                    };
                                    match serde_json::to_string_pretty(&data) {
                                        Ok(json) => match fs::write(&path, json) {
                                            Ok(_) => {
                                                self.save_status_msg = format!("Saved to {:?}", path);
                                                let _ = self.tx_sender.send(AppAction::ReloadWallets);
                                            }
                                            Err(e) => self.save_status_msg = format!("File Error: {}", e),
                                        },
                                        Err(e) => self.save_status_msg = format!("JSON Error: {}", e),
                                    }
                                }
                            }
                        });

                        if !self.save_status_msg.is_empty() {
                            ui.label(egui::RichText::new(&self.save_status_msg).color(egui::Color32::GREEN));
                        }
                    }
                });
            self.show_generator = open;
        }

        egui::SidePanel::left("left_panel")
            .resizable(true)
            .min_width(280.0)
            .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(format!("Wallets ({})", self.wallets.len()));
                if ui.button("🔄").clicked() {
                    let _ = self.tx_sender.send(AppAction::ReloadWallets);
                }
            });
            ui.separator();
            
            egui::ScrollArea::vertical()
                .auto_shrink([false, false]) 
                .show(ui, |ui| {
                for (i, wallet) in self.wallets.iter().enumerate() {
                    let selected = i == self.selected_wallet_idx;
                    let txt = format!("{}. {} ({:.4})", i+1, wallet.filename, wallet.balance);
                    if ui.selectable_label(selected, txt).clicked() {
                        self.selected_wallet_idx = i;
                        let rpc = self.get_rpc(&self.wallets[i]);
                        let _ = self.tx_sender.send(AppAction::RefreshBalance { idx: i, rpc });
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.wallets.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.heading("⚠️ No Wallets Found");
                    ui.label("Use 'Menu -> Create / Generate Wallet' to create a new wallet.");
                    ui.add_space(5.0);
                    ui.add(egui::TextEdit::multiline(&mut self.search_path.clone()).desired_width(f32::INFINITY));
                });
                return;
            }

            // PERBAIKAN: Clone wallet state agar tidak meminjam `self` secara permanen di scope ini
            let mut current_wallet = self.wallets[self.selected_wallet_idx].clone();

            ui.heading("Wallet Details");
            egui::ScrollArea::horizontal().id_source("info_scroll").show(ui, |ui| {
                egui::Grid::new("info_grid").striped(true).min_col_width(100.0).show(ui, |ui| {
                    ui.label("Filename:"); ui.label(&current_wallet.filename); ui.end_row();
                    
                    ui.label("Address:"); 
                    ui.horizontal(|ui| {
                        // Gunakan variable clone (current_wallet) yang sudah mutable
                        ui.add(egui::TextEdit::singleline(&mut current_wallet.address)
                            .desired_width(ui.available_width() - 40.0)); 
                        
                        if ui.button("📋").on_hover_text("Copy Address").clicked() {
                            ui.output_mut(|o| o.copied_text = current_wallet.address.clone());
                        }
                    });
                    ui.end_row();

                    ui.label("Balance:"); ui.heading(format!("{:.6} OCT", current_wallet.balance)); ui.end_row();
                    ui.label("Nonce:"); ui.label(format!("{}", current_wallet.nonce)); ui.end_row();
                });
            });
            
            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh Balance").clicked() {
                     // Pass reference ke clone
                     let rpc = self.get_rpc(&current_wallet);
                     let _ = self.tx_sender.send(AppAction::RefreshBalance { idx: self.selected_wallet_idx, rpc });
                }
                ui.checkbox(&mut self.use_default_rpc, "Use Default RPC");
            });
            ui.separator();

            ui.heading("Actions");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.batch_mode, BatchMode::SendSpecific, "Single / Batch Send");
                ui.selectable_value(&mut self.batch_mode, BatchMode::SweepToTarget, "Sweep to Addr");
                ui.selectable_value(&mut self.batch_mode, BatchMode::SweepToRandom, "Sweep to Random");
            });
            ui.separator();

            egui::ScrollArea::vertical().id_source("form_area").max_height(200.0).show(ui, |ui| {
                match self.batch_mode {
                    BatchMode::SendSpecific => {
                        ui.label("Target Address:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.batch_input_addr).desired_width(ui.available_width() - 80.0).hint_text("Paste address..."));
                            if ui.button("📋").on_hover_text("Paste").clicked() {
                                if let Some(cb) = &mut self.clipboard {
                                    if let Ok(text) = cb.get_text() { self.batch_input_addr = text; }
                                }
                            }
                            if ui.button("🔍").on_hover_text("Check Balance").clicked() {
                                let rpc = self.get_rpc(&current_wallet);
                                let _ = self.tx_sender.send(AppAction::CheckTargetBalance { addr: self.batch_input_addr.clone(), rpc });
                            }
                        });
                        ui.add_space(5.0);
                        ui.label("Amount:");
                        ui.add(egui::TextEdit::singleline(&mut self.batch_input_amt).desired_width(f32::INFINITY));
                    },
                    BatchMode::SweepToTarget => {
                        ui.label("Target Address:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.batch_input_addr).desired_width(ui.available_width() - 80.0).hint_text("Paste address..."));
                            if ui.button("📋").on_hover_text("Paste").clicked() {
                                if let Some(cb) = &mut self.clipboard {
                                    if let Ok(text) = cb.get_text() { self.batch_input_addr = text; }
                                }
                            }
                            if ui.button("🔍").on_hover_text("Check Balance").clicked() {
                                let rpc = self.get_rpc(&current_wallet);
                                let _ = self.tx_sender.send(AppAction::CheckTargetBalance { addr: self.batch_input_addr.clone(), rpc });
                            }
                        });
                    },
                    BatchMode::SweepToRandom => {
                        ui.label(format!("Source: {}", MY_WALLET_FILE));
                    }
                }
            });

            ui.separator();

            ui.heading("Execution Config");
            ui.horizontal(|ui| {
                ui.label("Start Index:");
                ui.add(egui::DragValue::new(&mut self.batch_start_idx));
                ui.label("Wallet Count:");
                ui.add(egui::DragValue::new(&mut self.batch_count));
            });

            if self.is_batch_running {
                if ui.add(egui::Button::new("🛑 STOP").fill(egui::Color32::RED).min_size(egui::vec2(150.0, 30.0))).clicked() {
                    self.stop_signal.store(true, Ordering::Relaxed);
                }
            } else {
                if ui.add(egui::Button::new("🚀 Execute Transaction").min_size(egui::vec2(150.0, 30.0))).clicked() {
                    let target_amt = self.batch_input_amt.parse::<f64>().ok();
                    if self.batch_count == 1 { self.batch_start_idx = self.selected_wallet_idx; }
                    
                    if self.batch_count == 1 {
                        let rpc = self.get_rpc(&current_wallet);
                        let _ = self.tx_sender.send(AppAction::SendTx { 
                            wallet_idx: self.batch_start_idx, 
                            to: self.batch_input_addr.clone(), 
                            amount: target_amt.unwrap_or(0.0), 
                            is_sweep: self.batch_mode != BatchMode::SendSpecific,
                            rpc 
                        });
                    } else {
                        self.stop_signal.store(false, Ordering::Relaxed);
                        self.is_batch_running = true;
                        self.batch_progress = 0.0;
                        let _ = self.tx_sender.send(AppAction::StartBatch {
                            mode: self.batch_mode.clone(),
                            start_idx: self.batch_start_idx,
                            count: self.batch_count,
                            target_addr: if self.batch_input_addr.is_empty() { None } else { Some(self.batch_input_addr.clone()) },
                            target_amount: target_amt,
                            rpc_override: self.get_rpc_override(),
                        });
                    }
                }
            }

            if self.is_batch_running {
                ui.add(egui::ProgressBar::new(self.batch_progress).show_percentage().animate(true));
            }

            ui.separator();

            ui.heading("Logs");
            egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                for log in &self.logs {
                    let color = if log.contains("SUCCESS") { egui::Color32::GREEN } 
                               else if log.contains("FAILED") || log.contains("ERROR") { egui::Color32::RED }
                               else if log.contains("STOP") { egui::Color32::YELLOW }
                               else { egui::Color32::GRAY };
                    ui.add(egui::Label::new(egui::RichText::new(log).color(color)).wrap(true));
                }
            });
        });
        
        ctx.request_repaint();
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native("Octra Wallet App", options, Box::new(|cc| Box::new(WalletApp::new(cc))))
}



//Code at https://github.com/maragung/