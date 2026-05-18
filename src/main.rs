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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};
use walkdir::WalkDir;

// 密钥缓存
lazy_static! {
    static ref KEY_CACHE: DashMap<Vec<u8>, [u8; 32]> = DashMap::new();
}

const MAGIC_HEADER: &str = "ENC_V1:";
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 12;

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

    // 2. 扫描文件
    println!("🔍 正在扫描当前目录下的加密文件...");
    let entries: Vec<PathBuf> = WalkDir::new(".")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    // 3. 过滤出加密文件
    let targets: Vec<PathBuf> = entries
        .into_iter()
        .filter(|p| {
            if let Ok(content) = fs::read_to_string(p) {
                return content.starts_with(MAGIC_HEADER);
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
            let res = decrypt_file(path, &password);
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

fn decrypt_file(path: &Path, password: &str) -> Result<()> {
    // 读取文件内容
    let content = fs::read_to_string(path).context("读取文件失败")?;
    
    // 只需要索引为 2 的 Payload 片段
    let segments: Vec<&str> = content.split(':').collect();
    if segments.len() < 3 {
        return Err(anyhow!("无效的结构: 缺少扩展区或载荷区"));
    }
    
    let payload_b64 = segments[2]; // 获取第二个冒号之后、第三个冒号之前（如果存在）的内容
    
    // Base64 解码载荷
    let combined = general_purpose::STANDARD.decode(payload_b64)
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
        argon2.hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("密钥派生失败: {:?}", e))?;
        
        // 存入缓存供其他相同 Salt 的文件使用
        KEY_CACHE.insert(salt.to_vec(), key);
        key
    };

    // 2. AES-256-GCM 解密
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| anyhow!("无效的密钥长度"))?;
    
    let nonce = Nonce::from_slice(iv);
    let decrypted_data = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("解密验证失败：密码错误或数据损坏"))?;

    // 3. 处理解压 (Deflate)
    let mut final_data = Vec::new();
    if compression_flag == 1 {
        // 使用 ZlibDecoder 来解析浏览器生成的 'deflate' 数据
        let mut decoder = ZlibDecoder::new(&decrypted_data[..]);
        decoder.read_to_end(&mut final_data)
            .context("数据解压失败 (ZLIB 格式异常)")?;
    } else {
        final_data = decrypted_data;
    }

    // 4. 写回还原后的明文
    fs::write(path, final_data).context("写入文件失败")?;

    Ok(())
}