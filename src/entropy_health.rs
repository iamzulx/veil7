// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Entropy health testing and monitoring.
//!
//! Implements health tests for entropy sources as recommended by NIST SP 800-90B:
//! - Repetition Count Test (RCT): detects stuck entropy sources
//! - Adaptive Proportion Test (APT): detects biased entropy sources
//! - Min-entropy estimation: ensures sufficient entropy quality
//! - Source diversity validation: validates sources are truly independent
//!
//! All tests follow the veil7 philosophy:
//! - No logs, no metadata, no trace
//! - Silent failures (return Result, no panic)
//! - Defence-in-depth (multiple health checks)
//! - Math over abstraction (statistical tests)

#[cfg(feature = "std")]
use super::EntropySource;

/// Repetition Count Test (RCT) — SP 800-90B Section 4.4.1
///
/// Detects stuck entropy sources by checking if the same value is repeated
/// too many times consecutively. A stuck source would produce the same
/// value repeatedly.
///
/// # Arguments
/// * `samples` - Raw entropy samples to test
/// * `cutoff` - Maximum allowed consecutive repetitions (typically 5-10)
///
/// # Returns
/// `true` if test passes (no stuck source detected), `false` if stuck source detected.
///
/// # Security
/// This is a health test, not a cryptographic primitive. It provides
/// defence-in-depth by detecting catastrophic entropy source failures.
pub fn repetition_count_test(samples: &[u8], cutoff: usize) -> bool {
    if samples.is_empty() {
        return true; // Empty samples pass (no stuck source)
    }

    let mut count = 1usize;
    let mut prev = samples[0];

    for &sample in &samples[1..] {
        if sample == prev {
            count += 1;
            if count >= cutoff {
                return false; // Stuck source detected
            }
        } else {
            prev = sample;
            count = 1;
        }
    }

    true // Test passed
}

/// Adaptive Proportion Test (APT) — SP 800-90B Section 4.4.2
///
/// Detects biased entropy sources by checking if any single value appears
/// too frequently in the sample set. A biased source would produce a
/// non-uniform distribution.
///
/// # Arguments
/// * `samples` - Raw entropy samples to test
/// * `cutoff` - Maximum allowed count for any single value (typically N/2)
///
/// # Returns
/// `true` if test passes (no bias detected), `false` if bias detected.
///
/// # Security
/// This is a health test, not a cryptographic primitive. It provides
/// defence-in-depth by detecting catastrophic entropy source failures.
pub fn adaptive_proportion_test(samples: &[u8], cutoff: usize) -> bool {
    if samples.is_empty() {
        return true; // Empty samples pass (no bias)
    }

    let mut counts = [0usize; 256];
    for &sample in samples {
        counts[sample as usize] += 1;
    }

    let mut max_count = 0usize;
    for count in counts {
        if count > max_count {
            max_count = count;
        }
    }
    max_count < cutoff
}

/// Estimate min-entropy of a sample set.
///
/// Min-entropy is the worst-case entropy measure:
///   H_min = -log2(max_probability)
///
/// where max_probability is the probability of the most likely sample value.
///
/// # Arguments
/// * `samples` - Raw entropy samples to test
///
/// # Returns
/// Estimated min-entropy in bits per sample (0.0 to 8.0 for byte samples).
///
/// # Security
/// This is an entropy quality metric, not a cryptographic primitive.
/// It provides defence-in-depth by ensuring sufficient entropy quality.
#[cfg(feature = "std")]
pub fn estimate_min_entropy(samples: &[u8]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &sample in samples {
        counts[sample as usize] += 1;
    }

    let mut max_count = 0usize;
    for count in counts {
        if count > max_count {
            max_count = count;
        }
    }
    let max_prob = max_count as f64 / samples.len() as f64;

    if max_prob <= 0.0 {
        return 0.0;
    }

    -max_prob.log2()
}

/// Validate source diversity by checking correlation between two sources.
///
/// Computes the Pearson correlation coefficient between two entropy sources.
/// Low correlation (< 0.1) indicates independent sources.
///
/// # Arguments
/// * `source1` - First entropy source samples
/// * `source2` - Second entropy source samples
///
/// # Returns
/// Correlation coefficient (-1.0 to 1.0). Values near 0 indicate independence.
///
/// # Security
/// This validates that entropy sources are truly independent, providing
/// defence-in-depth by ensuring source diversity.
#[cfg(feature = "std")]
pub fn validate_source_diversity(source1: &[u8], source2: &[u8]) -> f64 {
    let n = source1.len().min(source2.len());
    if n == 0 {
        return 0.0;
    }

    let mean1: f64 = source1[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    let mean2: f64 = source2[..n].iter().map(|&x| x as f64).sum::<f64>() / n as f64;

    let mut numerator = 0.0;
    let mut var1 = 0.0;
    let mut var2 = 0.0;

    for i in 0..n {
        let diff1 = source1[i] as f64 - mean1;
        let diff2 = source2[i] as f64 - mean2;
        numerator += diff1 * diff2;
        var1 += diff1 * diff1;
        var2 += diff2 * diff2;
    }

    if var1 <= 0.0 || var2 <= 0.0 {
        return 0.0; // No variance means no correlation
    }

    numerator / (var1.sqrt() * var2.sqrt())
}

/// Continuous entropy monitor.
///
/// Monitors entropy quality continuously and fails if quality drops below
/// threshold. Implements defence-in-depth by combining multiple health tests.
///
/// # Arguments
/// * `samples` - Raw entropy samples to test
/// * `min_entropy_threshold` - Minimum required min-entropy (typically 6.0-7.0 bits)
///
/// # Returns
/// `Ok(())` if all health tests pass, `Err` if any test fails.
///
/// # Security
/// This is a continuous health monitor, not a cryptographic primitive.
/// It provides defence-in-depth by failing safe on entropy quality degradation.
#[cfg(feature = "std")]
pub fn monitor_entropy_quality(
    samples: &[u8],
    min_entropy_threshold: f64,
) -> Result<(), &'static str> {
    // Test 1: Min-entropy
    let min_entropy = estimate_min_entropy(samples);
    if min_entropy < min_entropy_threshold {
        return Err("Entropy quality below threshold");
    }

    // Test 2: Repetition Count Test
    if !repetition_count_test(samples, 10) {
        return Err("Repetition count test failed");
    }

    // Test 3: Adaptive Proportion Test
    let cutoff = samples.len() / 2;
    if !adaptive_proportion_test(samples, cutoff) {
        return Err("Adaptive proportion test failed");
    }

    Ok(())
}

/// Run all health tests on an entropy source.
///
/// Convenience function that runs all health tests on an EntropySource.
///
/// # Arguments
/// * `source` - Entropy source to test
///
/// # Returns
/// `Ok(())` if all health tests pass, `Err` if any test fails.
#[cfg(feature = "std")]
pub fn health_check_source(source: &EntropySource) -> Result<(), &'static str> {
    let samples = source.raw();
    monitor_entropy_quality(samples, 6.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repetition_count_test_passes_on_uniform() {
        let samples: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(repetition_count_test(&samples, 10));
    }

    #[test]
    fn repetition_count_test_fails_on_stuck() {
        let samples = vec![0x42u8; 100]; // Stuck on 0x42
        assert!(!repetition_count_test(&samples, 10));
    }

    #[test]
    fn adaptive_proportion_test_passes_on_uniform() {
        let samples: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(adaptive_proportion_test(&samples, 500));
    }

    #[test]
    fn adaptive_proportion_test_fails_on_biased() {
        let mut samples = vec![0x42u8; 900]; // 90% bias
        samples.extend(vec![0x43u8; 100]);
        assert!(!adaptive_proportion_test(&samples, 500));
    }

    #[cfg(feature = "std")]
    #[test]
    fn estimate_min_entropy_uniform() {
        let samples: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = estimate_min_entropy(&samples);
        assert!(
            entropy > 7.0,
            "Uniform distribution should have high entropy"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn estimate_min_entropy_biased() {
        let samples = vec![0x42u8; 1000]; // All same value
        let entropy = estimate_min_entropy(&samples);
        assert!(entropy < 1.0, "Biased distribution should have low entropy");
    }

    #[cfg(feature = "std")]
    #[test]
    fn validate_source_diversity_independent() {
        // Use truly independent sources (not correlated)
        let source1: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        let source2: Vec<u8> = (0..100).map(|i| (i * 13 + 5) as u8).collect();
        let correlation = validate_source_diversity(&source1, &source2);
        assert!(
            correlation.abs() < 0.2,
            "Independent sources should have low correlation, got {}",
            correlation
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn validate_source_diversity_correlated() {
        let source1: Vec<u8> = (0..=255).cycle().take(100).collect();
        let source2 = source1.clone(); // Perfectly correlated
        let correlation = validate_source_diversity(&source1, &source2);
        assert!(
            correlation > 0.9,
            "Correlated sources should have high correlation"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn monitor_entropy_quality_passes_on_good_entropy() {
        let samples: Vec<u8> = (0..=255).cycle().take(1000).collect();
        assert!(monitor_entropy_quality(&samples, 6.0).is_ok());
    }

    #[cfg(feature = "std")]
    #[test]
    fn monitor_entropy_quality_fails_on_bad_entropy() {
        let samples = vec![0x42u8; 1000]; // Stuck source
        assert!(monitor_entropy_quality(&samples, 6.0).is_err());
    }

    #[test]
    fn test_rct_detects_stuck_source() {
        let samples = [0xAAu8; 100]; // 100 identical bytes
        assert!(
            !repetition_count_test(&samples, 10),
            "stuck source must be detected when cutoff=10"
        );
    }
}
