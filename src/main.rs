use clap::{Parser, Subcommand};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

// Helper function to convert Identifier to u16
fn identifier_to_u16(identifier: &frost::Identifier) -> u16 {
    let bytes = identifier.serialize();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "FROST 임계 서명 CLI 도구", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// DKG 프로토콜 실행 (키 생성)
    Dkg {
        /// 최대 서명자 수
        #[arg(short, long, default_value = "3")]
        max_signers: u16,
        
        /// 최소 서명자 수 (임계값)
        #[arg(short = 't', long, default_value = "2")]
        min_signers: u16,
        
        /// 출력 디렉토리
        #[arg(short, long, default_value = "frost_keys")]
        output_dir: PathBuf,
    },
    
    /// 서명 프로토콜 실행
    Sign {
        /// 키 디렉토리
        #[arg(short, long, default_value = "frost_keys")]
        key_dir: PathBuf,
        
        /// 서명할 메시지
        #[arg(short, long)]
        message: String,
        
        /// 서명에 참여할 참여자 ID (쉼표로 구분, 예: 1,3,5)
        #[arg(short, long)]
        signers: String,
    },
    
    /// 생성된 키 정보 확인
    Info {
        /// 키 디렉토리
        #[arg(short, long, default_value = "frost_keys")]
        key_dir: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyPackageData {
    identifier: String,
    key_package: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PubKeyPackageData {
    pubkey_package: Vec<u8>,
}

/// DKG Round 1 패키지를 저장하는 구조체
#[derive(Debug, Serialize, Deserialize)]
struct Round1Data {
    secret_package: Vec<u8>,
    public_packages: BTreeMap<String, Vec<u8>>,
}

/// DKG Round 2 패키지를 저장하는 구조체
#[derive(Debug, Serialize, Deserialize)]
struct Round2Data {
    secret_package: Vec<u8>,
    packages: BTreeMap<String, Vec<u8>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dkg {
            max_signers,
            min_signers,
            output_dir,
        } => {
            run_dkg(max_signers, min_signers, output_dir)?;
        }
        Commands::Sign {
            key_dir,
            message,
            signers,
        } => {
            run_sign(key_dir, message, signers)?;
        }
        Commands::Info { key_dir } => {
            show_info(key_dir)?;
        }
    }

    Ok(())
}

fn run_dkg(
    max_signers: u16,
    min_signers: u16,
    output_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 FROST DKG (Distributed Key Generation) 시작");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   최대 서명자: {}", max_signers);
    println!("   최소 서명자: {} (임계값)", min_signers);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // 출력 디렉토리 생성
    fs::create_dir_all(&output_dir)?;

    let mut rng = rand::thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 1
    ////////////////////////////////////////////////////////////////////////////
    println!("📍 Round 1: Commitment 생성 및 브로드캐스트");
    println!("   각 참여자가 commitment를 생성하고 다른 참여자들에게 전송합니다.\n");

    let mut round1_secret_packages = BTreeMap::new();
    let mut received_round1_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
            participant_identifier,
            max_signers,
            min_signers,
            &mut rng,
        )?;

        println!("   ✓ 참여자 {} - Round 1 패키지 생성", participant_index);

        // Store the participant's secret package
        round1_secret_packages.insert(participant_identifier, round1_secret_package);

        // Simulate broadcast: send to all other participants
        for receiver_participant_index in 1..=max_signers {
            if receiver_participant_index == participant_index {
                continue;
            }
            let receiver_participant_identifier: frost::Identifier = receiver_participant_index
                .try_into()
                .expect("should be nonzero");
            received_round1_packages
                .entry(receiver_participant_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round1_package.clone());
        }
    }

    println!("\n   💬 {} 개의 commitment가 브로드캐스트되었습니다.", max_signers);

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, Round 2
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 Round 2: Secret shares 생성 및 교환");
    println!("   각 참여자가 secret shares를 생성하고 다른 참여자들에게 개별 전송합니다.\n");

    let mut round2_secret_packages = BTreeMap::new();
    let mut received_round2_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round1_secret_package = round1_secret_packages
            .remove(&participant_identifier)
            .unwrap();
        let round1_packages = &received_round1_packages[&participant_identifier];
        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(round1_secret_package, round1_packages)?;

        println!("   ✓ 참여자 {} - Round 2 패키지 생성 ({} 개의 shares)", 
            participant_index, round2_packages.len());

        round2_secret_packages.insert(participant_identifier, round2_secret_package);

        // Send round 2 packages to specific participants
        for (receiver_identifier, round2_package) in round2_packages {
            received_round2_packages
                .entry(receiver_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(participant_identifier, round2_package);
        }
    }

    println!("\n   💬 Secret shares가 안전하게 교환되었습니다.");

    ////////////////////////////////////////////////////////////////////////////
    // Key generation, final computation
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 Round 3: 최종 키 생성");
    println!("   각 참여자가 받은 shares를 결합하여 최종 키를 생성합니다.\n");

    let mut key_packages = BTreeMap::new();
    let mut pubkey_packages = BTreeMap::new();

    for participant_index in 1..=max_signers {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        let round2_secret_package = &round2_secret_packages[&participant_identifier];
        let round1_packages = &received_round1_packages[&participant_identifier];
        let round2_packages = &received_round2_packages[&participant_identifier];
        let (key_package, pubkey_package) = frost::keys::dkg::part3(
            round2_secret_package,
            round1_packages,
            round2_packages,
        )?;

        println!("   ✓ 참여자 {} - 키 생성 완료", participant_index);

        key_packages.insert(participant_identifier, key_package);
        pubkey_packages.insert(participant_identifier, pubkey_package);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Save keys to disk
    ////////////////////////////////////////////////////////////////////////////
    println!("\n💾 키 저장 중...");

    // Save individual key packages
    for (identifier, key_package) in key_packages {
        let id_u16 = identifier_to_u16(&identifier);
        let key_data = KeyPackageData {
            identifier: id_u16.to_string(),
            key_package: serde_json::to_vec(&key_package)?,
        };
        
        let filename = output_dir.join(format!("participant_{}.json", id_u16));
        fs::write(&filename, serde_json::to_string_pretty(&key_data)?)?;
        println!("   ✓ {}", filename.display());
    }

    // Save public key package (same for all participants, save once)
    if let Some((_, pubkey_package)) = pubkey_packages.iter().next() {
        let pubkey_data = PubKeyPackageData {
            pubkey_package: serde_json::to_vec(pubkey_package)?,
        };
        
        let filename = output_dir.join("pubkey_package.json");
        fs::write(&filename, serde_json::to_string_pretty(&pubkey_data)?)?;
        println!("   ✓ {}", filename.display());
    }

    println!("\n✅ DKG 완료!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Display public key
    if let Some((_, pubkey_package)) = pubkey_packages.iter().next() {
        let pubkey_bytes = pubkey_package.verifying_key().serialize()?;
        let pubkey_hex = hex::encode(pubkey_bytes);
        println!("\n🔑 그룹 공개키:");
        println!("   {}", pubkey_hex);
    }

    println!("\n💡 다음 단계:");
    println!("   서명 생성: frost-cli sign -m \"your message\" -s \"1,3,5\"");
    println!("   키 정보 확인: frost-cli info\n");

    Ok(())
}

fn run_sign(
    key_dir: PathBuf,
    message: String,
    signers: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n✍️  FROST 서명 프로토콜 시작");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   메시지: \"{}\"", message);
    println!("   서명자: {}", signers);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Parse signer IDs
    let signer_ids: Vec<u16> = signers
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()?;

    if signer_ids.len() < 2 {
        return Err("최소 2명의 서명자가 필요합니다.".into());
    }

    let mut rng = rand::thread_rng();
    let message_bytes = message.as_bytes();

    // Load public key package
    let pubkey_file = key_dir.join("pubkey_package.json");
    let pubkey_data: PubKeyPackageData = serde_json::from_str(&fs::read_to_string(pubkey_file)?)?;
    let pubkey_package: frost::keys::PublicKeyPackage =
        serde_json::from_slice(&pubkey_data.pubkey_package)?;

    // Load key packages for signers
    let mut key_packages = BTreeMap::new();
    for &signer_id in &signer_ids {
        let key_file = key_dir.join(format!("participant_{}.json", signer_id));
        let key_data: KeyPackageData = serde_json::from_str(&fs::read_to_string(key_file)?)?;
        let key_package: frost::keys::KeyPackage =
            serde_json::from_slice(&key_data.key_package)?;
        let identifier = frost::Identifier::try_from(signer_id)?;
        key_packages.insert(identifier, key_package);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: Commitment generation
    ////////////////////////////////////////////////////////////////////////////
    println!("📍 서명 Round 1: Nonce commitments 생성");
    println!("   각 서명자가 nonce commitment를 생성합니다.\n");

    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for (identifier, key_package) in &key_packages {
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        let id_u16 = identifier_to_u16(identifier);
        println!("   ✓ 서명자 {} - Commitment 생성", id_u16);
        nonces_map.insert(*identifier, nonces);
        commitments_map.insert(*identifier, commitments);
    }

    println!("\n   💬 {} 개의 commitment가 공유되었습니다.", commitments_map.len());

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Signature share generation
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 Round 2: Signature shares 생성");
    println!("   각 서명자가 signature share를 생성합니다.\n");

    // Create signing package
    let signing_package = frost::SigningPackage::new(commitments_map.clone(), message_bytes);

    let mut signature_shares = BTreeMap::new();

    for (identifier, key_package) in &key_packages {
        let nonces = &nonces_map[identifier];
        let signature_share = frost::round2::sign(&signing_package, nonces, key_package)?;
        let id_u16 = identifier_to_u16(identifier);
        println!("   ✓ 서명자 {} - Signature share 생성", id_u16);
        signature_shares.insert(*identifier, signature_share);
    }

    println!("\n   💬 {} 개의 signature share가 수집되었습니다.", signature_shares.len());

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: Combine signature shares
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 집계");
    println!("   Coordinator가 signature shares를 결합합니다.\n");

    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;

    println!("   ✓ 서명 집계 완료");

    ////////////////////////////////////////////////////////////////////////////
    // Verification
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 검증");

    let is_valid = pubkey_package
        .verifying_key()
        .verify(message_bytes, &group_signature)
        .is_ok();

    if is_valid {
        println!("   ✅ 서명이 유효합니다!");
    } else {
        println!("   ❌ 서명이 유효하지 않습니다!");
        return Err("서명 검증 실패".into());
    }

    println!("\n✅ 서명 프로토콜 완료!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let sig_bytes = group_signature.serialize()?;
    let pubkey_bytes = pubkey_package.verifying_key().serialize()?;
    
    println!("\n📝 서명 정보:");
    println!("   서명: {}", hex::encode(&sig_bytes));
    println!("   공개키: {}", hex::encode(&pubkey_bytes));
    println!("   메시지: \"{}\"", message);
    println!("   서명자: {} 명 ({})", signer_ids.len(), 
        signer_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "));
    println!();

    Ok(())
}

fn show_info(key_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 FROST 키 정보");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Load public key package
    let pubkey_file = key_dir.join("pubkey_package.json");
    if !pubkey_file.exists() {
        return Err(format!("키 파일이 없습니다: {}", pubkey_file.display()).into());
    }

    let pubkey_data: PubKeyPackageData = serde_json::from_str(&fs::read_to_string(pubkey_file)?)?;
    let pubkey_package: frost::keys::PublicKeyPackage =
        serde_json::from_slice(&pubkey_data.pubkey_package)?;

    // Count participant files
    let mut participant_count = 0;
    for entry in fs::read_dir(&key_dir)? {
        let entry = entry?;
        let filename = entry.file_name();
        if filename.to_string_lossy().starts_with("participant_") {
            participant_count += 1;
        }
    }

    let pubkey_bytes = pubkey_package.verifying_key().serialize()?;
    
    println!("🔑 그룹 공개키:");
    println!("   {}", hex::encode(&pubkey_bytes));
    println!("\n👥 참여자:");
    println!("   총 {} 명의 참여자", participant_count);
    
    println!("\n📂 키 디렉토리:");
    println!("   {}", key_dir.display());
    
    println!("\n💡 사용 가능한 명령:");
    println!("   서명 생성: frost-cli sign -m \"message\" -s \"1,3,5\"");
    println!();

    Ok(())
}