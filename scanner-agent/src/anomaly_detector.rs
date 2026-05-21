//! ML-based Anomaly Detection
//!
//! Implements statistical anomaly detection using Z-score based outlier detection.
//! Features extracted from workload state for behavioral baseline comparison.

use serde::Serialize;
use std::collections::HashMap;

/// Feature vector for a workload
#[derive(Debug, Clone, Serialize)]
pub struct WorkloadFeatures {
    pub signal_count: f64,
    pub library_load_rate: f64,
    pub network_connection_count: f64,
    pub data_transfer_volume: f64,
    pub unique_syscall_count: f64,
    pub unique_file_path_count: f64,
    pub event_rate: f64,
    pub error_rate: f64,
}

impl WorkloadFeatures {
    /// Convert to a flat vector for statistical operations
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.signal_count,
            self.library_load_rate,
            self.network_connection_count,
            self.data_transfer_volume,
            self.unique_syscall_count,
            self.unique_file_path_count,
            self.event_rate,
            self.error_rate,
        ]
    }

    /// Number of features
    pub fn len(&self) -> usize {
        8
    }

    /// Check if features are empty
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Running statistics for a single feature
#[derive(Debug, Clone)]
struct RunningStats {
    count: u64,
    mean: f64,
    m2: f64, // For Welford's online variance
}

impl RunningStats {
    fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Update with a new value using Welford's online algorithm
    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Get variance
    fn variance(&self) -> f64 {
        if self.count < 2 {
            return 1.0; // Default variance for insufficient data
        }
        self.m2 / (self.count - 1) as f64
    }

    /// Get standard deviation
    fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Calculate Z-score for a value
    fn z_score(&self, value: f64) -> f64 {
        let std = self.std_dev();
        if std < 1e-10 {
            return 0.0;
        }
        (value - self.mean) / std
    }
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    pub workload_id: String,
    pub is_anomalous: bool,
    pub anomaly_score: f64,
    pub anomalous_features: Vec<AnomalousFeature>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalousFeature {
    pub feature_name: String,
    pub value: f64,
    pub z_score: f64,
    pub mean: f64,
    pub std_dev: f64,
}

/// Statistical anomaly detector
pub struct AnomalyDetector {
    /// Running statistics per feature
    feature_stats: Vec<RunningStats>,
    /// Z-score threshold for anomaly detection
    threshold: f64,
    /// Minimum samples before detection starts
    min_samples: u64,
    /// Number of features
    feature_count: usize,
}

impl AnomalyDetector {
    pub fn new(threshold: f64, min_samples: u64) -> Self {
        let feature_count = 8; // Number of features in WorkloadFeatures
        Self {
            feature_stats: vec![RunningStats::new(); feature_count],
            threshold,
            min_samples,
            feature_count,
        }
    }

    /// Update baseline with new feature data
    pub fn update_baseline(&mut self, features: &WorkloadFeatures) {
        let values = features.to_vec();
        for (i, value) in values.iter().enumerate() {
            if i < self.feature_count {
                self.feature_stats[i].update(*value);
            }
        }
    }

    /// Check if a workload is anomalous
    pub fn detect(&self, workload_id: &str, features: &WorkloadFeatures) -> AnomalyResult {
        // Need minimum samples for meaningful detection
        if self.feature_stats[0].count < self.min_samples {
            return AnomalyResult {
                workload_id: workload_id.to_string(),
                is_anomalous: false,
                anomaly_score: 0.0,
                anomalous_features: Vec::new(),
                timestamp: chrono::Utc::now(),
            };
        }

        let values = features.to_vec();
        let mut anomalous_features = Vec::new();
        let mut max_z_score = 0.0f64;

        let feature_names = [
            "signal_count",
            "library_load_rate",
            "network_connection_count",
            "data_transfer_volume",
            "unique_syscall_count",
            "unique_file_path_count",
            "event_rate",
            "error_rate",
        ];

        for (i, value) in values.iter().enumerate() {
            if i < self.feature_count {
                let z_score = self.feature_stats[i].z_score(*value).abs();
                max_z_score = max_z_score.max(z_score);

                if z_score > self.threshold {
                    anomalous_features.push(AnomalousFeature {
                        feature_name: feature_names[i].to_string(),
                        value: *value,
                        z_score,
                        mean: self.feature_stats[i].mean,
                        std_dev: self.feature_stats[i].std_dev(),
                    });
                }
            }
        }

        // Normalize anomaly score to 0-1 range
        let anomaly_score = (max_z_score / (self.threshold * 2.0)).min(1.0);

        AnomalyResult {
            workload_id: workload_id.to_string(),
            is_anomalous: !anomalous_features.is_empty(),
            anomaly_score,
            anomalous_features,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Get current baseline statistics
    pub fn baseline_stats(&self) -> Vec<BaselineStat> {
        let feature_names = [
            "signal_count",
            "library_load_rate",
            "network_connection_count",
            "data_transfer_volume",
            "unique_syscall_count",
            "unique_file_path_count",
            "event_rate",
            "error_rate",
        ];

        self.feature_stats
            .iter()
            .enumerate()
            .map(|(i, stats)| BaselineStat {
                feature_name: feature_names[i].to_string(),
                mean: stats.mean,
                std_dev: stats.std_dev(),
                count: stats.count,
            })
            .collect()
    }

    /// Reset baseline statistics
    pub fn reset(&mut self) {
        self.feature_stats = vec![RunningStats::new(); self.feature_count];
    }
}

/// Baseline statistics for a feature
#[derive(Debug, Serialize)]
pub struct BaselineStat {
    pub feature_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_running_stats() {
        let mut stats = RunningStats::new();
        stats.update(10.0);
        stats.update(20.0);
        stats.update(30.0);

        assert!((stats.mean - 20.0).abs() < 0.01);
        assert!(stats.std_dev() > 0.0);
    }

    #[test]
    fn test_anomaly_detection() {
        let mut detector = AnomalyDetector::new(2.0, 10);

        // Train with normal data
        for i in 0..20 {
            let features = WorkloadFeatures {
                signal_count: 5.0 + (i as f64 * 0.1),
                library_load_rate: 1.0,
                network_connection_count: 3.0,
                data_transfer_volume: 1000.0,
                unique_syscall_count: 10.0,
                unique_file_path_count: 20.0,
                event_rate: 50.0,
                error_rate: 0.01,
            };
            detector.update_baseline(&features);
        }

        // Test with normal data
        let normal = WorkloadFeatures {
            signal_count: 5.5,
            library_load_rate: 1.1,
            network_connection_count: 3.2,
            data_transfer_volume: 1100.0,
            unique_syscall_count: 11.0,
            unique_file_path_count: 22.0,
            event_rate: 52.0,
            error_rate: 0.02,
        };
        let result = detector.detect("normal", &normal);
        assert!(!result.is_anomalous);

        // Test with anomalous data
        let anomalous = WorkloadFeatures {
            signal_count: 100.0, // Very high
            library_load_rate: 1.0,
            network_connection_count: 3.0,
            data_transfer_volume: 1000.0,
            unique_syscall_count: 10.0,
            unique_file_path_count: 20.0,
            event_rate: 50.0,
            error_rate: 0.01,
        };
        let result = detector.detect("anomalous", &anomalous);
        assert!(result.is_anomalous);
    }
}
