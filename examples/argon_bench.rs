use argon2::{Algorithm, Argon2, Params, Version};
use std::time::Instant;

fn hash_ms(m_kib: u32, t: u32, p: u32) -> f64 {
    let params = Params::new(m_kib, t, p, Some(32)).unwrap();
    let a = Argon2::new_with_secret(b"a 32 byte pepper for benchmarking", Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    let mut times: Vec<f64> = (0..5)
        .map(|_| {
            let t0 = Instant::now();
            a.hash_password_into(b"correct horse battery staple", b"0123456789abcdef", &mut out).unwrap();
            t0.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[2]
}

/// n hashes at once on n threads: how throughput scales when several logins arrive together.
fn concurrent_ms(m_kib: u32, t: u32, n: usize) -> f64 {
    let t0 = Instant::now();
    let hs: Vec<_> = (0..n).map(|_| std::thread::spawn(move || hash_ms(m_kib, t, 1))).collect();
    let each: Vec<f64> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let _ = t0;
    each.iter().sum::<f64>() / each.len() as f64
}

fn main() {
    println!("{:<34} {:>10} {:>14}", "memory / passes / parallelism", "time (ms)", "guesses/s (1 thread)");
    for (label, m, t, p) in [
        ("19 MiB / 2 / 1   <- current", 19 * 1024, 2, 1),
        ("46 MiB / 1 / 1   (OWASP alt)", 46 * 1024, 1, 1),
        ("64 MiB / 3 / 1", 64 * 1024, 3, 1),
        ("128 MiB / 3 / 1", 128 * 1024, 3, 1),
        ("256 MiB / 3 / 1", 256 * 1024, 3, 1),
        ("512 MiB / 3 / 1", 512 * 1024, 3, 1),
        ("64 MiB / 3 / 4  (RFC 9106 alt)", 64 * 1024, 3, 4),
    ] {
        let ms = hash_ms(m, t, p);
        println!("{label:<34} {ms:>10.1} {:>14.1}", 1000.0 / ms);
    }
    println!("\nseveral at once (average time each, 64 MiB / 3 passes):");
    for n in [1, 2, 4, 8, 16] {
        println!("  {n:>2} at once: {:>7.1} ms each", concurrent_ms(64 * 1024, 3, n));
    }
}
