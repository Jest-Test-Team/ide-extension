/// Shannon entropy in bits per symbol (byte).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    #[test]
    fn entropy() {
        assert_eq!(super::shannon(b"aaaa"), 0.0);
        assert!((super::shannon(b"abcd") - 2.0).abs() < 1e-9);
        let all: Vec<u8> = (0..=255).collect();
        assert!((super::shannon(&all) - 8.0).abs() < 1e-9);
    }
}
