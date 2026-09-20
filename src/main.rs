use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use dashmap::DashMap;
use flate2::read::ZlibDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use rayon::prelude::*;
use std::borrow::Cow;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};
use walkdir::WalkDir;

// 密钥缓存：针对 V1 缓存基于随机 Salt 派生的对称密钥
lazy_static! {
    static ref KEY_CACHE: DashMap<Vec<u8>, [u8; 32]> = DashMap::new();
    // 密钥缓存：针对 V2 缓存基于 EDEK (ek) 解密还原后的数据密钥 (DEK)
    static ref DEK_CACHE: DashMap<String, [u8; 32]> = DashMap::new();
}

const MAGIC_HEADER: &str = "ENC_V2:";
const MAGIC_HEADER_V1: &str = "ENC_V1:";
const KEK_SALT: &[u8] = b"Phantom_Cipher_KEK_Salt_V2_2026";
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 分块解密步长：4MB

/// 仅提取解密运行所需的核心元数据字段
#[derive(Default, Debug)]
struct DecryptionParams {
    cp: Option<u8>,     // cp: 压缩标识 (1: 启用 Deflate, 0: 未压缩)
    ek: Option<String>, // ek: 加密后的 DEK 数据包
    bf: Option<u8>,     // bf: 载荷格式 (1: 原生二进制, 0: Base64 文本)
}

/// 解析 Key=Value&... 扩展区中的核心解密键
fn parse_decryption_params(ext_str: &str) -> DecryptionParams {
    let mut params = DecryptionParams::default();
    if ext_str.is_empty() {
        return params;
    }
    for part in ext_str.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "cp" => {
                    if let Ok(val) = v.parse::<u8>() {
                        params.cp = Some(val);
                    }
                }
                "bf" => {
                    if let Ok(val) = v.parse::<u8>() {
                        params.bf = Some(val);
                    }
                }
                "ek" => params.ek = Some(v.to_string()),
                _ => {}
            }
        }
    }
    params
}

/// 派生主密钥 (KEK) - 仅根据主密码与固定 KEK_SALT 执行一次 Argon2id 运算
fn derive_kek(password: &str) -> Result<[u8; 32]> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 参数错误: {:?}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), KEK_SALT, &mut kek)
        .map_err(|e| anyhow!("主密钥 (KEK) 派生失败: {:?}", e))?;
    Ok(kek)
}

fn main() -> Result<()> {
    println!("👻 PhantomCipher 离线解密工具");
    println!("---------------------------------");

    // 1. 获取密码输入
    print!("请输入主密码: ");
    std::io::stdout().flush().context("无法刷新 stdout")?;
    let password = rpassword::read_password().context("读取密码失败")?;
    if password.is_empty() {
        return Err(anyhow!("密码不能为空"));
    }

    // 派生主密钥 (KEK)，供 V2 文件直接复用信封解密
    println!("🔑 正在派生 V2 主密钥 (KEK)...");
    let kek = derive_kek(&password)?;
    let kek_cipher = Aes256Gcm::new_from_slice(&kek)
        .map_err(|_| anyhow!("无效的 KEK 密钥长度"))?;

    // 2. 扫描文件
    println!("🔍 正在扫描当前目录下的加密文件...");
    let entries: Vec<PathBuf> = WalkDir::new(".")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    // 3. 过滤出加密文件：同时兼容扫描 ENC_V1 与 ENC_V2 格式文件
    let targets: Vec<PathBuf> = entries
        .into_iter()
        .filter(|p| {
            if let Ok(mut file) = fs::File::open(p) {
                let mut head = [0u8; 7];
                if file.read_exact(&mut head).is_ok() {
                    return head == MAGIC_HEADER.as_bytes() || head == MAGIC_HEADER_V1.as_bytes();
                }
            }
            false
        })
        .collect();

    if targets.is_empty() {
        println!("✅ 未发现加密文件。");
        return Ok(());
    }

    println!("🚀 发现 {} 个加密文件，开始解密...", targets.len());
    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    // 4. 并行解密
    let results: Vec<Result<()>> = targets
        .par_iter()
        .map(|path| {
            let res = decrypt_file(path, &password, &kek_cipher);
            pb.inc(1);
            res
        })
        .collect();

    pb.finish_with_message("处理完成");

    // 5. 统计结果
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let fail_count = results.len() - success_count;

    println!("\n✨ 处理报告:");
    println!("成功: {} 个文件", success_count);
    if fail_count > 0 {
        println!("失败: {} 个文件", fail_count);
        // 打印具体错误列表
        for (i, res) in results.iter().enumerate() {
            if let Err(e) = res {
                println!("  - [{}] 错误: {}", targets[i].display(), e);
            }
        }
    }

    Ok(())
}

/// V1 格式解密链路：单包结构直接解密
fn decrypt_v1(raw_data: &[u8], password: &str) -> Result<Vec<u8>> {
    let content = std::str::from_utf8(raw_data).context("V1 文件非有效 UTF-8 文本")?;

    // 只需要索引为 2 的 Payload 片段
    let segments: Vec<&str> = content.split(':').collect();
    if segments.len() < 3 {
        return Err(anyhow!("无效的结构: 缺少扩展区或载荷区"));
    }

    let payload_b64 = segments[2]; // 获取第二个冒号之后的内容

    // Base64 解码载荷
    let combined = general_purpose::STANDARD
        .decode(payload_b64.trim())
        .context("Payload Base64 解码失败")?;

    if combined.len() < SALT_SIZE + IV_SIZE + 1 {
        return Err(anyhow!("密文数据长度异常"));
    }

    // 拆分结构：Salt(16) + IV(12) + Flag(1) + Ciphertext(n)
    let salt = &combined[0..SALT_SIZE];
    let iv = &combined[SALT_SIZE..SALT_SIZE + IV_SIZE];
    let compression_flag = combined[SALT_SIZE + IV_SIZE];
    let ciphertext = &combined[SALT_SIZE + IV_SIZE + 1..];

    // 检查缓存中是否已有针对此 Salt 的密钥
    let derived_key = if let Some(cached_key) = KEY_CACHE.get(salt) {
        *cached_key
    } else {
        // 缓存缺失：执行 Argon2id 派生
        let params = Params::new(65536, 3, 4, Some(32))
            .map_err(|e| anyhow!("Argon2 参数错误: {:?}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("密钥派生失败: {:?}", e))?;

        // 存入缓存供其他相同 Salt 的文件使用
        KEY_CACHE.insert(salt.to_vec(), key);
        key
    };

    // 2. AES-256-GCM 解密
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| anyhow!("无效的密钥长度"))?;

    let nonce = Nonce::from_slice(iv);
    let decrypted_data = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("解密验证失败：密码错误或数据损坏"))?;

    // 3. 处理解压 (Deflate)
    let mut final_data = Vec::new();
    if compression_flag == 1 {
        // 使用 ZlibDecoder 来解析浏览器生成的 'deflate' 数据
        let mut decoder = ZlibDecoder::new(&decrypted_data[..]);
        decoder
            .read_to_end(&mut final_data)
            .context("数据解压失败 (ZLIB 格式异常)")?;
    } else {
        final_data = decrypted_data;
    }

    Ok(final_data)
}

/// V2 格式解密链路：信封架构与分块流解密
fn decrypt_v2(raw_data: &[u8], kek_cipher: &Aes256Gcm) -> Result<Vec<u8>> {
    // 只需要索引为 2 的 Payload 片段：定位分隔冒号提取扩展元数据区与密文载荷区
    let scan_limit = raw_data.len().min(2048);
    let header_end_index = raw_data[MAGIC_HEADER.len()..scan_limit]
        .iter()
        .position(|&b| b == b':')
        .map(|pos| MAGIC_HEADER.len() + pos)
        .ok_or_else(|| anyhow!("未找到扩展区结束分隔符"))?;

    let ext_str = std::str::from_utf8(&raw_data[MAGIC_HEADER.len()..header_end_index])
        .context("扩展区非有效 UTF-8 编码")?;
    let params = parse_decryption_params(ext_str);

    // Base64 解码载荷：根据 bf 标识判断载荷类型，bf=1 为原生二进制，否则按 Base64 解码
    let combined: Cow<'_, [u8]> = if params.bf == Some(1) {
        Cow::Borrowed(&raw_data[header_end_index + 1..])
    } else {
        let b64_slice = &raw_data[header_end_index + 1..];
        let b64_str = std::str::from_utf8(b64_slice).context("密文载荷非有效 UTF-8 文本")?;
        let decoded = general_purpose::STANDARD
            .decode(b64_str.trim())
            .context("Payload Base64 解码失败")?;
        Cow::Owned(decoded)
    };

    let ek_str = params
        .ek
        .as_deref()
        .ok_or_else(|| anyhow!("元数据块缺失 EDEK (ek 字段)"))?;

    // 检查缓存中是否已有针对此 Salt 的密钥；V2 检查缓存中是否已有当前 EDEK 对应的 DEK
    let dek_bytes = if let Some(cached_dek) = DEK_CACHE.get(ek_str) {
        *cached_dek
    } else {
        // 缓存缺失：执行 Argon2id 派生（主密钥 KEK）并在解密 EDEK 时还原 DEK
        let combined_edek = general_purpose::STANDARD
            .decode(ek_str)
            .context("EDEK Base64 解码失败")?;

        if combined_edek.len() < IV_SIZE + TAG_SIZE {
            return Err(anyhow!("EDEK 载荷长度不足"));
        }

        let nonce = Nonce::from_slice(&combined_edek[..IV_SIZE]);
        let ciphertext = &combined_edek[IV_SIZE..];

        let decrypted_dek = kek_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("解密 EDEK 失败：密码错误"))?;

        if decrypted_dek.len() != 32 {
            return Err(anyhow!("DEK 长度非 32 字节"));
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&decrypted_dek);

        // 存入缓存供其他相同 Salt 的文件使用；V2 存入缓存供使用相同 EDEK 的其他文件复用
        DEK_CACHE.insert(ek_str.to_string(), dek);
        dek
    };

    // 拆分结构：Salt(16) + IV(12) + Flag(1) + Ciphertext(n)；V2 采用分块流结构，每块由 IV(12) + Ciphertext + Tag(16) 组成
    let chunk_cipher_unit = CHUNK_SIZE + IV_SIZE + TAG_SIZE;
    if combined.len() < IV_SIZE + TAG_SIZE {
        return Err(anyhow!("密文数据长度小于最小分块开销"));
    }

    let num_chunks = std::cmp::max(1, (combined.len() + chunk_cipher_unit - 1) / chunk_cipher_unit);
    let plain_total_estimate = combined.len().saturating_sub(num_chunks * (IV_SIZE + TAG_SIZE));
    let mut decrypted_data = Vec::with_capacity(plain_total_estimate);

    // 2. AES-256-GCM 解密：使用 DEK 对载荷进行分块解密
    let dek_cipher = Aes256Gcm::new_from_slice(&dek_bytes)
        .map_err(|_| anyhow!("无效的 DEK 密钥"))?;

    for i in 0..num_chunks {
        let cipher_offset = i * chunk_cipher_unit;
        let current_chunk_size = std::cmp::min(combined.len() - cipher_offset, chunk_cipher_unit);

        if current_chunk_size < IV_SIZE + TAG_SIZE {
            return Err(anyhow!("分块数据不完整"));
        }

        let iv = &combined[cipher_offset..cipher_offset + IV_SIZE];
        let ciphertext = &combined[cipher_offset + IV_SIZE..cipher_offset + current_chunk_size];

        let nonce = Nonce::from_slice(iv);
        let dec_chunk = dek_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("分块解密失败：密文损坏或验证标签不匹配"))?;

        decrypted_data.extend_from_slice(&dec_chunk);
    }

    // 3. 处理解压 (Deflate)
    let mut final_data = Vec::new();
    let compression_flag = params.cp.unwrap_or(0);
    if compression_flag == 1 {
        // 使用 ZlibDecoder 来解析浏览器生成的 'deflate' 数据
        let mut decoder = ZlibDecoder::new(&decrypted_data[..]);
        decoder
            .read_to_end(&mut final_data)
            .context("数据解压失败 (ZLIB 格式异常)")?;
    } else {
        final_data = decrypted_data;
    }

    Ok(final_data)
}

fn decrypt_file(path: &Path, password: &str, kek_cipher: &Aes256Gcm) -> Result<()> {
    // 读取文件内容：读取原始字节流以兼容文本及二进制文件
    let raw_data = fs::read(path).context("读取文件失败")?;

    let final_data = if raw_data.starts_with(MAGIC_HEADER.as_bytes()) {
        decrypt_v2(&raw_data, kek_cipher)?
    } else if raw_data.starts_with(MAGIC_HEADER_V1.as_bytes()) {
        decrypt_v1(&raw_data, password)?
    } else {
        return Err(anyhow!("未识别的加密标头"));
    };

    // 4. 写回还原后的明文
    fs::write(path, final_data).context("写入文件失败")?;

    Ok(())
}