use aes::cipher::{KeyIvInit, StreamCipher as AesStreamCipher};
use aes::Aes256;
use chacha20::cipher::{NewCipher, StreamCipher as ChaChaStreamCipher};
use chacha20::ChaCha20;
use ctr::Ctr128BE;
use rand::rngs::OsRng;
use rand::RngCore;
use rayon::ThreadPoolBuilder;
use rfd::FileDialog;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::PublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
type MyResult<T> = Result<T, Box<dyn std::error::Error>>;
fn encode_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
fn decode_hex(s: &str) -> MyResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err("Ungültiger Hex-String".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.into()))
        .collect()
}
fn recursive_files(path: &Path) -> MyResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(recursive_files(&path)?);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}
type Aes256Ctr = Ctr128BE<Aes256>;
fn format_filename(name: &str) -> String {
    let max_len = 15;
    if name.chars().count() > max_len {
        let truncated: String = name.chars().take(max_len - 3).collect();
        format!("{}...", truncated)
    } else {
        format!("{:width$}", name, width = max_len)
    }
}
struct FileProgress {
    original_path: String,
    new_path: String,
    total_bytes: u64,
    processed_bytes: u64,
    start_time: Instant,
}
impl FileProgress {
    fn new(original_path: String, total_bytes: u64) -> Self {
        Self {
            original_path,
            new_path: String::from("pending"),
            total_bytes,
            processed_bytes: 0,
            start_time: Instant::now(),
        }
    }
}
fn get_chunk_size() -> usize {
    64 * 1024
}
fn encrypt_rsa(data: &[u8], public_key_pem: &str) -> MyResult<Vec<u8>> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)?;
    let mut rng = OsRng;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let encrypted = public_key.encrypt(&mut rng, padding, data)?;
    Ok(encrypted)
}
fn decrypt_rsa(data: &[u8], priv_key_path: &str) -> MyResult<Vec<u8>> {
    let priv_key_pem = fs::read_to_string(priv_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&priv_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&priv_key_pem))?;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let decrypted = private_key.decrypt(padding, data)?;
    Ok(decrypted)
}
fn encrypt_data(
    data: &mut [u8],
    key_aes: &[u8],
    key_chacha: &[u8],
    cipher_aes: &mut Aes256Ctr,
    cipher_chacha: &mut ChaCha20,
) -> MyResult<()> {
    cipher_aes.apply_keystream(data);
    cipher_chacha
        .try_apply_keystream(data)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("ChaCha20 Fehler beim Verschlüsseln: {:?}", e).into()
        })?;
    Ok(())
}
fn decrypt_data(
    data: &mut [u8],
    key_aes: &[u8],
    key_chacha: &[u8],
    cipher_aes: &mut Aes256Ctr,
    cipher_chacha: &mut ChaCha20,
) -> MyResult<()> {
    cipher_chacha
        .try_apply_keystream(data)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("ChaCha20 Fehler beim Entschlüsseln: {:?}", e).into()
        })?;
    cipher_aes.apply_keystream(data);
    Ok(())
}
fn encrypt_filename(filename: &str, key: &[u8]) -> MyResult<String> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut cipher = ChaCha20::new_from_slices(key, &nonce)
        .map_err(|e| format!("Fehler beim Erstellen des ChaCha20-Ciphers: {:?}", e))?;
    let mut data = filename.as_bytes().to_vec();
    cipher.try_apply_keystream(&mut data).map_err(|e| {
        format!(
            "ChaCha20 Fehler beim Verschlüsseln des Dateinamens: {:?}",
            e
        )
    })?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&data);
    Ok(encode_hex(&combined))
}
fn decrypt_filename(enc_filename: &str, key: &[u8]) -> MyResult<String> {
    let combined = decode_hex(enc_filename)?;
    if combined.len() < 12 {
        return Err("Ungültiger verschlüsselter Dateiname".into());
    }
    let (nonce, ciphertext) = combined.split_at(12);
    let mut cipher = ChaCha20::new_from_slices(key, nonce)
        .map_err(|e| format!("Fehler beim Erstellen des ChaCha20-Ciphers: {:?}", e))?;
    let mut data = ciphertext.to_vec();
    cipher.try_apply_keystream(&mut data).map_err(|e| {
        format!(
            "ChaCha20 Fehler beim Entschlüsseln des Dateinamens: {:?}",
            e
        )
    })?;
    let filename = String::from_utf8(data)?;
    Ok(filename)
}
fn encrypt_file(
    file_path: &Path,
    public_key: &str,
    progress: &Arc<Mutex<FileProgress>>,
) -> MyResult<()> {
    let mut master_key = [0u8; 64];
    OsRng.fill_bytes(&mut master_key);
    let key_aes = &master_key[..32];
    let key_chacha = &master_key[32..];
    let encrypted_key = encrypt_rsa(&master_key, public_key)?;
    let folder_path = file_path.parent().unwrap_or(Path::new("."));
    let original_filename = file_path.file_name().unwrap().to_string_lossy().to_string();
    let enc_filename = encrypt_filename(&original_filename, key_aes)?;
    let enc_file_path = folder_path.join(format!("{}.enc", enc_filename));
    {
        let mut prog = progress.lock().unwrap();
        prog.new_path = enc_file_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
    }
    let mut input_file = File::open(file_path)?;
    let mut output_file = File::create(&enc_file_path)?;
    output_file.write_all(&encrypted_key)?;
    let mut nonce_aes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_aes);
    output_file.write_all(&nonce_aes)?;
    let mut nonce_chacha = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_chacha);
    output_file.write_all(&nonce_chacha)?;
    let mut cipher_aes = Aes256Ctr::new(key_aes.into(), &nonce_aes.into());
    let mut cipher_chacha = ChaCha20::new_from_slices(key_chacha, &nonce_chacha)
        .map_err(|e| format!("Fehler beim Erstellen des ChaCha20-Ciphers: {:?}", e))?;
    let chunk_size = get_chunk_size();
    let mut buffer = vec![0u8; chunk_size];
    while let Ok(n) = input_file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let mut data_chunk = buffer[..n].to_vec();
        encrypt_data(
            &mut data_chunk,
            key_aes,
            key_chacha,
            &mut cipher_aes,
            &mut cipher_chacha,
        )?;
        output_file.write_all(&data_chunk)?;
        {
            let mut prog = progress.lock().unwrap();
            prog.processed_bytes += n as u64;
        }
    }
    fs::remove_file(file_path)?;
    Ok(())
}
fn decrypt_file(
    file_path: &Path,
    priv_key_path: &str,
    encrypted_key_length: usize,
    progress: &Arc<Mutex<FileProgress>>,
) -> MyResult<()> {
    let mut input_file = File::open(file_path)?;
    let mut encrypted_key = vec![0u8; encrypted_key_length];
    input_file.read_exact(&mut encrypted_key)?;
    let mut nonce_aes = [0u8; 16];
    input_file.read_exact(&mut nonce_aes)?;
    let mut nonce_chacha = [0u8; 12];
    input_file.read_exact(&mut nonce_chacha)?;
    let master_key = decrypt_rsa(&encrypted_key, priv_key_path)?;
    if master_key.len() < 64 {
        return Err("Masterkey hat ungültige Länge".into());
    }
    let key_aes = &master_key[..32];
    let key_chacha = &master_key[32..];
    let folder_path = file_path.parent().unwrap_or(Path::new("."));
    let enc_filename = file_path.file_stem().unwrap().to_string_lossy().to_string();
    let original_filename = decrypt_filename(&enc_filename, key_aes)?;
    let dec_file_path = folder_path.join(&original_filename);
    {
        let mut prog = progress.lock().unwrap();
        prog.new_path = original_filename.clone();
    }
    let mut output_file = File::create(&dec_file_path)?;
    let mut cipher_aes = Aes256Ctr::new(key_aes.into(), &nonce_aes.into());
    let mut cipher_chacha = ChaCha20::new_from_slices(key_chacha, &nonce_chacha)
        .map_err(|e| format!("Fehler beim Erstellen des ChaCha20-Ciphers: {:?}", e))?;
    let chunk_size = get_chunk_size();
    let mut buffer = vec![0u8; chunk_size];
    while let Ok(n) = input_file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let mut data_chunk = buffer[..n].to_vec();
        decrypt_data(
            &mut data_chunk,
            key_aes,
            key_chacha,
            &mut cipher_aes,
            &mut cipher_chacha,
        )?;
        output_file.write_all(&data_chunk)?;
        {
            let mut prog = progress.lock().unwrap();
            prog.processed_bytes += n as u64;
        }
    }
    fs::remove_file(file_path)?;
    Ok(())
}
fn process_file(
    file_path: &Path,
    public_key: &str,
    priv_key_path: &str,
    encrypted_key_length: usize,
    action: &str,
    progress: Arc<Mutex<FileProgress>>,
) -> MyResult<()> {
    if action == "decrypt" {
        if file_path
            .extension()
            .map(|ext| ext == "enc")
            .unwrap_or(false)
        {
            decrypt_file(file_path, priv_key_path, encrypted_key_length, &progress)?;
        }
    } else if action == "encrypt" {
        if !file_path
            .extension()
            .map(|ext| ext == "enc")
            .unwrap_or(false)
        {
            encrypt_file(file_path, public_key, &progress)?;
        }
    }
    Ok(())
}
fn run_process_directory(
    directory: &Path,
    public_key: &str,
    priv_key_path: &str,
    num_processes: usize,
    encrypted_key_length: usize,
    action: &str,
    visualize_debug: bool,
) -> MyResult<()> {
    let files = recursive_files(directory)?;
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|path| {
            if action == "encrypt" {
                !path.extension().map(|ext| ext == "enc").unwrap_or(false)
            } else if action == "decrypt" {
                path.extension().map(|ext| ext == "enc").unwrap_or(false)
            } else {
                false
            }
        })
        .collect();
    let total_folder_size: u64 = files
        .iter()
        .map(|path| fs::metadata(path).map(|meta| meta.len()).unwrap_or(0))
        .sum();
    println!("Gesamtgröße des Ordners: {} Bytes", total_folder_size);
    let progress_list: Arc<Mutex<Vec<Arc<Mutex<FileProgress>>>>> = Arc::new(Mutex::new(Vec::new()));
    for path in &files {
        if let Ok(meta) = fs::metadata(path) {
            let total = if action == "decrypt" {
                meta.len()
                    .saturating_sub((encrypted_key_length + 28) as u64)
            } else {
                meta.len()
            };
            let prog = Arc::new(Mutex::new(FileProgress::new(
                path.file_name().unwrap().to_string_lossy().to_string(),
                total,
            )));
            progress_list.lock().unwrap().push(prog);
        }
    }
    let overall_start = Instant::now();
    let all_done = Arc::new(AtomicBool::new(false));
    let mut progress_thread_handle = None;
    if visualize_debug {
        let progress_list_clone = Arc::clone(&progress_list);
        let all_done_clone = Arc::clone(&all_done);
        print!("\x1B[2J\x1B[H");
        println!(
            "{: <15} -> {: <15} | {:>16}",
            "Original File", "Target File", "Geschwindigkeit"
        );
        println!("{}", "-".repeat(70));
        io::stdout().flush().unwrap();
        progress_thread_handle = Some(std::thread::spawn(move || {
            let total_rows = {
                let list = progress_list_clone.lock().unwrap();
                list.len()
            };
            loop {
                print!("\x1B[3;1H");
                let mut rows = Vec::new();
                {
                    let list = progress_list_clone.lock().unwrap();
                    for file_prog in list.iter() {
                        let prog = file_prog.lock().unwrap();
                        if prog.new_path == "pending" {
                            continue;
                        }
                        let elapsed = prog.start_time.elapsed().as_secs_f64();
                        let speed = if elapsed > 0.0 {
                            prog.processed_bytes as f64 / elapsed
                        } else {
                            0.0
                        };
                        rows.push(format!(
                            "[DEBUG] {} -> {} | {:>10.0} B/s",
                            format_filename(&prog.original_path),
                            format_filename(&prog.new_path),
                            speed
                        ));
                    }
                }
                for row in &rows {
                    println!("{}", row);
                }
                for _ in rows.len()..total_rows {
                    println!("{: <80}", " ");
                }
                io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_millis(10));
                if all_done_clone.load(Ordering::Relaxed) {
                    break;
                }
            }
        }));
    }
    ThreadPoolBuilder::new()
        .num_threads(num_processes)
        .build()?
        .scope(|s| {
            let list = progress_list.lock().unwrap();
            let progress_records = list.clone();
            drop(list);
            for (i, file_path) in files.into_iter().enumerate() {
                let public_key = public_key.to_string();
                let priv_key_path = priv_key_path.to_string();
                let action = action.to_string();
                let file_progress = Arc::clone(&progress_records[i]);
                s.spawn(move |_| {
                    if let Err(e) = process_file(
                        &file_path,
                        &public_key,
                        &priv_key_path,
                        encrypted_key_length,
                        &action,
                        file_progress,
                    ) {
                        eprintln!("Fehler bei {:?}: {}", file_path, e);
                    }
                });
            }
        });
    all_done.store(true, Ordering::Relaxed);
    if let Some(handle) = progress_thread_handle {
        handle.join().unwrap();
    }
    let mut report = String::new();
    report.push_str(&format!(
        "{: <15} -> {: <15} | {:>16}\n",
        "Original File", "Target File", "Geschwindigkeit"
    ));
    report.push_str(&"-".repeat(70));
    report.push('\n');
    let list = progress_list.lock().unwrap();
    let total_files = list.len();
    let mut completed_files = 0;
    for file_prog in list.iter() {
        let prog = file_prog.lock().unwrap();
        if prog.new_path == "pending" {
            continue;
        }
        let elapsed = prog.start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 {
            prog.processed_bytes as f64 / elapsed
        } else {
            0.0
        };
        if prog.processed_bytes >= prog.total_bytes {
            completed_files += 1;
        }
        report.push_str(&format!(
            "[DEBUG] {} -> {} | {:>10.0} B/s\n",
            format_filename(&prog.original_path),
            format_filename(&prog.new_path),
            speed
        ));
    }
    report.push('\n');
    let overall_elapsed = overall_start.elapsed().as_secs_f64();
    let overall_speed = if overall_elapsed > 0.0 {
        total_folder_size as f64 / overall_elapsed
    } else {
        0.0
    };
    report.push_str(&format!(
        "[DEBUG SUMMARY] Debugged: {} Dateien, verarbeitet: {} Dateien\n",
        total_files, completed_files
    ));
    report.push_str(&format!(
        "Gesamtgröße: {} Bytes, Gesamtzeit: {:.2} Sekunden, Durchschnittliche Geschwindigkeit: {:.0} B/s\n",
        total_folder_size, overall_elapsed, overall_speed
    ));
    fs::write("debug.txt", report)?;
    println!("Prozess abgeschlossen. Debug-Report in debug.txt geschrieben.");
    println!(
        "Gesamtverarbeitungszeit: {:.2} Sekunden, Durchschnittliche Geschwindigkeit: {:.0} B/s",
        overall_elapsed, overall_speed
    );
    Ok(())
}
fn main() -> MyResult<()> {
    println!("Welcome to Jimmy's secure encrypter/decrypter");
    println!("This tool will encrypt all files in a folder to protect your data.");
    println!("Press any key to continue...");
    let mut dummy = String::new();
    io::stdin().read_line(&mut dummy)?;
    if dummy.trim() == "--version" {
        println!("Version 1.1");
        println!("Press any key to continue...");
        dummy.clear();
        io::stdin().read_line(&mut dummy)?;
    }

    println!("Would you like to enable debug visualization? (type 'on' or 'off')");
    let mut debug_choice = String::new();
    io::stdin().read_line(&mut debug_choice)?;
    let visualize_debug = debug_choice.trim().eq_ignore_ascii_case("on");

    let action = loop {
        println!("Do you want to encrypt or decrypt files? (type 'encrypt' or 'decrypt'):");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let action = input.trim().to_lowercase();
        if action == "encrypt" || action == "decrypt" {
            break action;
        }
    };

    let folder = FileDialog::new()
        .set_title("Select folder to encrypt/decrypt")
        .pick_folder();
    let folder = match folder {
        Some(path) => path,
        None => {
            println!("No folder selected. Exiting.");
            return Ok(());
        }
    };

    let key_length_str = fs::read_to_string("key_length.txt")?;
    let key_length: usize = key_length_str.trim().parse()?;
    let encrypted_key_length = key_length / 8;

    println!("CPU: Generic CPU");
    let available_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!("Available CPU cores: {}", available_cores);

    let num_processes = loop {
        println!(
            "Please enter the number of CPU cores to use (1–{}):",
            available_cores
        );
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().parse::<usize>() {
            Ok(n) if n > 0 && n <= available_cores => break n,
            _ => println!("Invalid input. Enter a number between 1 and {}.", available_cores),
        }
    };

    let priv_key_path = "priv.key";
    let pub_key_path = "pub.key";
    if Path::new(priv_key_path).exists() && Path::new(pub_key_path).exists() {
        let public_key = fs::read_to_string(pub_key_path)?;
        run_process_directory(
            &folder,
            &public_key,
            priv_key_path,
            num_processes,
            encrypted_key_length,
            &action,
            visualize_debug,
        )?;
    } else {
        if !Path::new(priv_key_path).exists() {
            println!("Private key file 'priv.key' not found.");
        }
        if !Path::new(pub_key_path).exists() {
            println!("Public key file 'pub.key' not found.");
        }
    }

    println!("Process complete. Press Enter to exit...");
    let mut exit_dummy = String::new();
    io::stdin().read_line(&mut exit_dummy)?;
    Ok(())
}
