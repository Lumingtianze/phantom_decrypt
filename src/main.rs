use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use flate2::read::ZlibDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, io::Write};
use walkdir::WalkDir;

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
            if let Ok(mut f) = fs::File::open(p) {
                let mut head = [0u8; 7]; // "ENC_V1:" 的长度是 7
                if f.read_exact(&mut head).is_ok() {
                    return head == MAGIC_HEADER.as_bytes();
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
            let res = decrypt_file(path, &password);
            pb.inc(1);
            res
        })
        .collect();

    pb.finish_with_message("完成");

    // 5. 统计结果
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    let fail_count = results.len() - success_count;

    println!("\n✨ 处理报告:");
    println!("成功: {} 个文件", success_count);
    if fail_count > 0 {
        println!("失败: {} 个文件 (请检查密码是否正确)", fail_count);
        // 打印第一个失败的错误原因供参考
        if let Some(Err(e)) = results.iter().find(|r| r.is_err()) {
            println!("首个失败原因示例: {}", e);
        }
    }

    Ok(())
}

fn decrypt_file(path: &Path, password: &str) -> Result<()> {
    // 读取文件内容
    let content = fs::read_to_string(path).context("读取文件失败")?;
    if !content.starts_with(MAGIC_HEADER) {
        return Err(anyhow!("不是有效的加密文件"));
    }

    let armored_text = &content[MAGIC_HEADER.len()..];
    
    // Base64 解码
    let combined = general_purpose::STANDARD.decode(armored_text)
        .context("Base64 解码失败")?;

    if combined.len() < SALT_SIZE + IV_SIZE + 1 {
        return Err(anyhow!("密文数据过短，可能已损坏"));
    }

    // 拆分结构：Salt(16) + IV(12) + Flag(1) + Ciphertext(n)
    let salt = &combined[0..SALT_SIZE];
    let iv = &combined[SALT_SIZE..SALT_SIZE + IV_SIZE];
    let compression_flag = combined[SALT_SIZE + IV_SIZE];
    let ciphertext = &combined[SALT_SIZE + IV_SIZE + 1..];

    // 1. 派生密钥 (Argon2id)
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 参数错误: {:?}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let mut derived_key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow!("密钥派生失败: {:?}", e))?;

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
            .context("数据解压失败 (ZLIB 格式错误)")?;
    } else {
        final_data = decrypted_data;
    }


    // 4. 覆盖原始文件
    fs::write(path, final_data).context("写入还原文件失败")?;

    Ok(())
}