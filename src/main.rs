// Cargo.toml:
// [package]
// name = "frost-cli"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// frost-ed25519 = "2.0.0"
// clap = { version = "4.5", features = ["derive"] }
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// hex = "0.4"
// rand = "0.8"
// tokio = { version = "1", features = ["full"] }
// libp2p = { version = "0.53", features = ["noise", "tcp", "tokio", "macros", "gossipsub", "mdns", "yamux"] }
// futures = "0.3"
// anyhow = "1.0"

use clap::{Parser, Subcommand};
use frost_ed25519 as frost;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, PeerId, Swarm, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

// Helper function to convert Identifier to u16
fn identifier_to_u16(identifier: &frost::Identifier) -> u16 {
    let bytes = identifier.serialize();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "FROST 임계 서명 CLI 도구 (P2P 네트워크)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// DKG 프로토콜 실행 (키 생성)
    Dkg {
        /// 참여자 ID (1, 2, 또는 3)
        #[arg(short, long)]
        id: u16,
        
        /// 리스닝 포트
        #[arg(short, long, default_value = "0")]
        port: u16,
        
        /// 출력 디렉토리
        #[arg(short, long, default_value = "frost_keys")]
        output_dir: PathBuf,
    },
    
    /// 서명 프로토콜 실행
    Sign {
        /// 참여자 ID
        #[arg(short, long)]
        id: u16,
        
        /// 키 디렉토리
        #[arg(short = 'k', long, default_value = "frost_keys")]
        key_dir: PathBuf,
        
        /// 서명할 메시지
        #[arg(short, long)]
        message: String,
        
        /// 리스닝 포트
        #[arg(short, long, default_value = "0")]
        port: u16,
    },
    
    /// 생성된 키 정보 확인
    Info {
        /// 키 디렉토리
        #[arg(short = 'k', long, default_value = "frost_keys")]
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

/// FROST 프로토콜 메시지
#[derive(Debug, Clone, Serialize, Deserialize)]
enum FrostMessage {
    // DKG Round 1
    DkgRound1 {
        sender_id: u16,
        package: Vec<u8>,
    },
    // DKG Round 2
    DkgRound2 {
        sender_id: u16,
        packages: Vec<(u16, Vec<u8>)>, // (recipient_id, package)
    },
    // DKG Complete
    DkgComplete {
        sender_id: u16,
    },
    // Sign Round 1
    SignRound1 {
        sender_id: u16,
        commitment: Vec<u8>,
    },
    // Sign Round 2
    SignRound2 {
        sender_id: u16,
        signature_share: Vec<u8>,
    },
}

/// 네트워크 동작 정의
#[derive(NetworkBehaviour)]
struct FrostBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/// P2P 네트워크 노드
struct P2PNode {
    swarm: Swarm<FrostBehaviour>,
    participant_id: u16,
    message_tx: mpsc::UnboundedSender<FrostMessage>,
    message_rx: mpsc::UnboundedReceiver<FrostMessage>,
}

impl P2PNode {
    async fn new(participant_id: u16, port: u16) -> Result<Self, Box<dyn Error>> {
        // 키 페어 생성
        let id_keys = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());
        
        println!("🆔 Local PeerId: {}", peer_id);
        println!("👤 Participant ID: {}", participant_id);

        // Gossipsub 설정
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| format!("Gossipsub config error: {}", e))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(id_keys.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("Gossipsub creation error: {}", e))?;

        // FROST 토픽 구독
        let topic = gossipsub::IdentTopic::new("frost");
        gossipsub.subscribe(&topic)?;

        // mDNS로 로컬 네트워크에서 피어 발견
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            peer_id,
        )?;

        let behaviour = FrostBehaviour { gossipsub, mdns };

        // Swarm 생성
        let mut swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // 리스닝 주소 설정
        let listen_addr = if port == 0 {
            format!("/ip4/0.0.0.0/tcp/0")
        } else {
            format!("/ip4/0.0.0.0/tcp/{}", port)
        };
        
        swarm.listen_on(listen_addr.parse()?)?;

        let (message_tx, message_rx) = mpsc::unbounded_channel();

        Ok(Self {
            swarm,
            participant_id,
            message_tx,
            message_rx,
        })
    }

    async fn run(mut self, msg_handler_tx: mpsc::UnboundedSender<FrostMessage>) -> Result<(), Box<dyn Error>> {
        let topic = gossipsub::IdentTopic::new("frost");

        loop {
            tokio::select! {
                // 외부에서 전송할 메시지 받기
                Some(message) = self.message_rx.recv() => {
                    let data = serde_json::to_vec(&message)?;
                    // 메시지 발행 재시도 로직
                    match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data.clone()) {
                        Ok(_) => {
                            // 성공
                        }
                        Err(e) => {
                            // 피어가 없을 때는 잠시 대기 후 재시도
                            eprintln!("⚠️  Publish warning: {} (재시도 중...)", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            if let Err(e2) = self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                                eprintln!("❌ Publish error after retry: {}", e2);
                            }
                        }
                    }
                }
                // 네트워크 이벤트 처리
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("🎧 Listening on: {}", address);
                        }
                        SwarmEvent::Behaviour(FrostBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, multiaddr) in list {
                                println!("🔍 Discovered peer: {} at {}", peer_id, multiaddr);
                                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(FrostBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _) in list {
                                println!("👋 Peer expired: {}", peer_id);
                                self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        SwarmEvent::Behaviour(FrostBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            message,
                            ..
                        })) => {
                            if let Ok(frost_msg) = serde_json::from_slice::<FrostMessage>(&message.data) {
                                // 자신이 보낸 메시지는 무시
                                let sender_id = match &frost_msg {
                                    FrostMessage::DkgRound1 { sender_id, .. } => *sender_id,
                                    FrostMessage::DkgRound2 { sender_id, .. } => *sender_id,
                                    FrostMessage::DkgComplete { sender_id } => *sender_id,
                                    FrostMessage::SignRound1 { sender_id, .. } => *sender_id,
                                    FrostMessage::SignRound2 { sender_id, .. } => *sender_id,
                                };
                                
                                if sender_id != self.participant_id {
                                    println!("📨 Received message from participant {}", sender_id);
                                    let _ = msg_handler_tx.send(frost_msg);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(FrostBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            println!("✅ Peer {} subscribed to topic: {}", peer_id, topic);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            println!("🤝 Connected to: {}", peer_id);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn get_sender(&self) -> mpsc::UnboundedSender<FrostMessage> {
        self.message_tx.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dkg {
            id,
            port,
            output_dir,
        } => {
            run_dkg(id, port, output_dir).await?;
        }
        Commands::Sign {
            id,
            key_dir,
            message,
            port,
        } => {
            run_sign(id, key_dir, message, port).await?;
        }
        Commands::Info { key_dir } => {
            show_info(key_dir)?;
        }
    }

    Ok(())
}

async fn run_dkg(
    participant_id: u16,
    port: u16,
    output_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    const MAX_SIGNERS: u16 = 3;
    const MIN_SIGNERS: u16 = 2;

    if participant_id < 1 || participant_id > MAX_SIGNERS {
        return Err(format!("Participant ID must be between 1 and {}", MAX_SIGNERS).into());
    }

    println!("\n🔐 FROST DKG (Distributed Key Generation) 시작");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   참여자 ID: {}", participant_id);
    println!("   최대 서명자: {}", MAX_SIGNERS);
    println!("   최소 서명자: {} (임계값)", MIN_SIGNERS);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    fs::create_dir_all(&output_dir)?;

    // P2P 노드 시작
    let node = P2PNode::new(participant_id, port).await?;
    let network_tx = node.get_sender();
    let (msg_rx_tx, mut msg_rx) = mpsc::unbounded_channel();

    // 네트워크 태스크 시작
    tokio::spawn(async move {
        if let Err(e) = node.run(msg_rx_tx).await {
            eprintln!("Network error: {}", e);
        }
    });

    // 피어 발견 및 gossipsub 연결 대기
    println!("⏳ 다른 참여자 발견 및 연결 대기 중...");
    
    let start = std::time::Instant::now();
    let mut peer_count = 0;
    let required_peers = (MAX_SIGNERS - 1) as usize;
    
    // 최대 30초 대기하면서 필요한 수의 피어가 연결될 때까지 기다림
    while peer_count < required_peers && start.elapsed().as_secs() < 30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        // 간단한 카운터 (실제로는 네트워크 이벤트로 확인하지만 여기서는 시간 기반)
        if start.elapsed().as_secs() >= 10 {
            peer_count = required_peers; // 10초 후에는 준비되었다고 가정
        }
    }
    
    println!("✅ 네트워크 준비 완료 ({} 초 경과)", start.elapsed().as_secs());

    let mut rng = rand::thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // DKG Round 1
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 Round 1: Commitment 생성 및 브로드캐스트");

    let identifier = frost::Identifier::try_from(participant_id)?;
    let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
        identifier,
        MAX_SIGNERS,
        MIN_SIGNERS,
        &mut rng,
    )?;

    println!("   ✓ Round 1 패키지 생성");

    // 브로드캐스트
    let msg = FrostMessage::DkgRound1 {
        sender_id: participant_id,
        package: serde_json::to_vec(&round1_package)?,
    };
    network_tx.send(msg)?;
    println!("   📤 Round 1 패키지 브로드캐스트");

    // 다른 참여자들의 Round 1 패키지 수집
    println!("\n⏳ 다른 참여자들의 Round 1 패키지 대기 중...");
    let mut round1_packages = BTreeMap::new();
    // 자신의 패키지도 추가 (part2에 필요)
    round1_packages.insert(identifier, round1_package.clone());

    let expected_count = MAX_SIGNERS - 1;
    let mut received_count = 0;

    while received_count < expected_count {
        if let Some(msg) = msg_rx.recv().await {
            if let FrostMessage::DkgRound1 { sender_id, package } = msg {
                let pkg: frost::keys::dkg::round1::Package = serde_json::from_slice(&package)?;
                let sender_identifier = frost::Identifier::try_from(sender_id)?;
                round1_packages.insert(sender_identifier, pkg);
                received_count += 1;
                println!("   ✓ 참여자 {}로부터 Round 1 패키지 수신 ({}/{})", 
                    sender_id, received_count, expected_count);
            }
        }
    }

    println!("   💬 Round 1 패키지 수집 완료 (총 {} 개, 자신 포함)", round1_packages.len());

    ////////////////////////////////////////////////////////////////////////////
    // DKG Round 2
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 Round 2: Secret shares 생성 및 브로드캐스트");
    println!("   디버그: round1_packages 수 = {} (예상: {})", round1_packages.len(), MAX_SIGNERS);

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, &round1_packages)
            .map_err(|e| format!("part2 실패: {:?}", e))?;

    println!("   ✓ Round 2 패키지 생성 ({} 개, 예상: {})", round2_packages.len(), MAX_SIGNERS - 1);

    // Round 2 패키지를 직렬화하여 브로드캐스트
    // 주의: round2_packages에는 다른 모든 참여자에 대한 패키지가 포함됨
    let mut packages_vec = Vec::new();
    for (recipient_id, package) in &round2_packages {
        let recipient_u16 = identifier_to_u16(recipient_id);
        packages_vec.push((recipient_u16, serde_json::to_vec(package)?));
    }

    let msg = FrostMessage::DkgRound2 {
        sender_id: participant_id,
        packages: packages_vec,
    };
    network_tx.send(msg)?;
    println!("   📤 Round 2 패키지 브로드캐스트 ({} 개 패키지)", round2_packages.len());

    // 다른 참여자들의 Round 2 패키지 수집
    println!("\n⏳ 다른 참여자들의 Round 2 패키지 대기 중...");
    let mut round2_packages_received = BTreeMap::new();
    received_count = 0;

    // 자신을 제외한 다른 모든 참여자로부터 패키지를 받아야 함
    while received_count < expected_count {
        if let Some(msg) = msg_rx.recv().await {
            if let FrostMessage::DkgRound2 { sender_id, packages } = msg {
                let sender_identifier = frost::Identifier::try_from(sender_id)?;
                
                // 자신에게 온 패키지 찾기
                for (recipient_id, package_data) in packages {
                    if recipient_id == participant_id {
                        let pkg: frost::keys::dkg::round2::Package = 
                            serde_json::from_slice(&package_data)?;
                        round2_packages_received.insert(sender_identifier, pkg);
                        received_count += 1;
                        println!("   ✓ 참여자 {}로부터 Round 2 패키지 수신 ({}/{})", 
                            sender_id, received_count, expected_count);
                        break;
                    }
                }
            }
        }
    }

    println!("   💬 Round 2 패키지 수집 완료 (총 {} 개)", round2_packages_received.len());

    ////////////////////////////////////////////////////////////////////////////
    // DKG Round 3: 최종 키 생성
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 Round 3: 최종 키 생성");
    println!("   디버그: round1_packages 수 = {}", round1_packages.len());
    println!("   디버그: round2_packages_received 수 = {}", round2_packages_received.len());

    let (key_package, pubkey_package) = frost::keys::dkg::part3(
        &round2_secret_package,
        &round1_packages,
        &round2_packages_received,
    )?;

    println!("   ✓ 키 생성 완료");

    // 완료 신호 브로드캐스트
    network_tx.send(FrostMessage::DkgComplete {
        sender_id: participant_id,
    })?;

    // 키 저장
    println!("\n💾 키 저장 중...");

    let key_data = KeyPackageData {
        identifier: participant_id.to_string(),
        key_package: serde_json::to_vec(&key_package)?,
    };

    let filename = output_dir.join(format!("participant_{}.json", participant_id));
    fs::write(&filename, serde_json::to_string_pretty(&key_data)?)?;
    println!("   ✓ {}", filename.display());

    let pubkey_data = PubKeyPackageData {
        pubkey_package: serde_json::to_vec(&pubkey_package)?,
    };

    let pubkey_filename = output_dir.join("pubkey_package.json");
    fs::write(&pubkey_filename, serde_json::to_string_pretty(&pubkey_data)?)?;
    println!("   ✓ {}", pubkey_filename.display());

    println!("\n✅ DKG 완료!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let pubkey_bytes = pubkey_package.verifying_key().serialize()?;
    println!("\n🔑 그룹 공개키:");
    println!("   {}", hex::encode(&pubkey_bytes));

    println!("\n💡 다음 단계:");
    println!("   서명 생성: frost-cli sign --id {} -m \"your message\"", participant_id);
    println!();

    // 네트워크 유지 (다른 참여자 대기)
    println!("⏳ 다른 참여자들의 완료 대기 중...");
    let mut completed = 1; // 자신 포함
    while completed < MAX_SIGNERS {
        if let Some(msg) = msg_rx.recv().await {
            if let FrostMessage::DkgComplete { .. } = msg {
                completed += 1;
                println!("   ✓ 완료 신호 수신 ({}/{})", completed, MAX_SIGNERS);
            }
        }
    }

    println!("\n🎉 모든 참여자가 DKG 완료!\n");

    Ok(())
}

async fn run_sign(
    participant_id: u16,
    key_dir: PathBuf,
    message: String,
    port: u16,
) -> Result<(), Box<dyn Error>> {
    const MAX_SIGNERS: u16 = 3;
    const MIN_SIGNERS: u16 = 2;

    println!("\n✍️  FROST 서명 프로토콜 시작");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   참여자 ID: {}", participant_id);
    println!("   메시지: \"{}\"", message);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let mut rng = rand::thread_rng();
    let message_bytes = message.as_bytes();

    // 키 로드
    let key_file = key_dir.join(format!("participant_{}.json", participant_id));
    let key_data: KeyPackageData = serde_json::from_str(&fs::read_to_string(key_file)?)?;
    let key_package: frost::keys::KeyPackage = serde_json::from_slice(&key_data.key_package)?;

    let pubkey_file = key_dir.join("pubkey_package.json");
    let pubkey_data: PubKeyPackageData = serde_json::from_str(&fs::read_to_string(pubkey_file)?)?;
    let pubkey_package: frost::keys::PublicKeyPackage =
        serde_json::from_slice(&pubkey_data.pubkey_package)?;

    // P2P 노드 시작
    let node = P2PNode::new(participant_id, port).await?;
    let network_tx = node.get_sender();
    let (msg_rx_tx, mut msg_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        if let Err(e) = node.run(msg_rx_tx).await {
            eprintln!("Network error: {}", e);
        }
    });

    println!("⏳ 다른 서명자 발견 및 연결 대기 중...");
    tokio::time::sleep(Duration::from_secs(10)).await;

    ////////////////////////////////////////////////////////////////////////////
    // Sign Round 1
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 Round 1: Nonce commitments 생성");

    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    let msg = FrostMessage::SignRound1 {
        sender_id: participant_id,
        commitment: serde_json::to_vec(&commitments)?,
    };
    network_tx.send(msg)?;
    println!("   ✓ Commitment 생성 및 브로드캐스트");

    // 다른 서명자들의 commitments 수집
    println!("\n⏳ 다른 서명자들의 commitments 대기 중... (최소 {} 명)", MIN_SIGNERS - 1);
    let mut commitments_map = BTreeMap::new();
    let identifier = frost::Identifier::try_from(participant_id)?;
    commitments_map.insert(identifier, commitments);

    let mut received_count = 0;
    let min_required = MIN_SIGNERS - 1;

    // 타임아웃 설정
    let timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(msg) = msg_rx.recv() => {
                if let FrostMessage::SignRound1 { sender_id, commitment } = msg {
                    let comm: frost::round1::SigningCommitments = 
                        serde_json::from_slice(&commitment)?;
                    let sender_identifier = frost::Identifier::try_from(sender_id)?;
                    commitments_map.insert(sender_identifier, comm);
                    received_count += 1;
                    println!("   ✓ 참여자 {}로부터 commitment 수신 ({}/{})", 
                        sender_id, received_count, min_required);
                    
                    if received_count >= min_required {
                        break;
                    }
                }
            }
            _ = &mut timeout => {
                if received_count >= min_required {
                    break;
                }
                return Err(format!(
                    "타임아웃: {} 명의 서명자만 참여 (최소 {} 명 필요)",
                    received_count + 1, MIN_SIGNERS
                ).into());
            }
        }
    }

    println!("\n   💬 총 {} 명의 서명자 참여", commitments_map.len());

    ////////////////////////////////////////////////////////////////////////////
    // Sign Round 2
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 Round 2: Signature shares 생성");

    let signing_package = frost::SigningPackage::new(commitments_map.clone(), message_bytes);
    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)?;

    let msg = FrostMessage::SignRound2 {
        sender_id: participant_id,
        signature_share: serde_json::to_vec(&signature_share)?,
    };
    network_tx.send(msg)?;
    println!("   ✓ Signature share 생성 및 브로드캐스트");

    // 다른 서명자들의 signature shares 수집
    println!("\n⏳ 다른 서명자들의 signature shares 대기 중...");
    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(identifier, signature_share);

    let mut received_count = 0;
    let expected_shares = commitments_map.len() - 1;

    let timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(msg) = msg_rx.recv() => {
                if let FrostMessage::SignRound2 { sender_id, signature_share } = msg {
                    let sender_identifier = frost::Identifier::try_from(sender_id)?;
                    
                    // 이 서명자가 Round 1에 참여했는지 확인
                    if commitments_map.contains_key(&sender_identifier) {
                        let share: frost::round2::SignatureShare = 
                            serde_json::from_slice(&signature_share)?;
                        signature_shares.insert(sender_identifier, share);
                        received_count += 1;
                        println!("   ✓ 참여자 {}로부터 signature share 수신 ({}/{})", 
                            sender_id, received_count, expected_shares);
                        
                        if received_count >= expected_shares {
                            break;
                        }
                    }
                }
            }
            _ = &mut timeout => {
                return Err("타임아웃: signature shares 수집 실패".into());
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // 서명 집계
    ////////////////////////////////////////////////////////////////////////////
    println!("\n📍 서명 집계");

    let group_signature = frost::aggregate(&signing_package, &signature_shares, &pubkey_package)?;
    println!("   ✓ 서명 집계 완료");

    ////////////////////////////////////////////////////////////////////////////
    // 검증
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
    println!("   서명자: {} 명", signature_shares.len());
    println!();

    Ok(())
}

fn show_info(key_dir: PathBuf) -> Result<(), Box<dyn Error>> {
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
    println!("   최소 서명자: 2 명 (임계값)");

    println!("\n📂 키 디렉토리:");
    println!("   {}", key_dir.display());

    println!("\n💡 사용 가능한 명령:");
    println!("   서명 생성: frost-cli sign --id <ID> -m \"message\"");
    println!();

    Ok(())
}