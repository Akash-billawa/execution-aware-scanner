//! Predictive Risk Scoring
//!
//! Time-series risk prediction using Exponentially Weighted Moving Average (EWMA).
//! Predicts future risk scores based on historical trends.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// Risk snapshot for a CVE
#[derive(Debug, Clone, Serialize)]
pub struct RiskSnapshot {
    pub timestamp: DateTime<Utc>,
    pub score: f32,
    pub cvss: f32,
    pub epss: f32,
    pub kev: bool,
    pub runtime_signal: f32,
    pub event_rate: f64,
    pub network_activity: f64,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum TrendDirection {
    Rising,
    Falling,
    Stable,
}

/// Predicted risk for a CVE
#[derive(Debug, Clone, Serialize)]
pub struct PredictedRisk {
    pub cve_id: String,
    pub current_score: f32,
    pub predicted_1h: f32,
    pub predicted_4h: f32,
    pub predicted_24h: f32,
    pub trend: TrendDirection,
    pub confidence: f32,
    pub data_points: usize,
    pub last_updated: DateTime<Utc>,
}

/// EWMA configuration
#[derive(Debug, Clone)]
pub struct EwmaConfig {
    /// Smoothing factor (0 < alpha <= 1). Higher = more weight on recent data
    pub alpha: f64,
    /// Minimum data points before prediction starts
    pub min_data_points: usize,
    /// Maximum history to keep per CVE
    pub max_history: usize,
}

impl Default for EwmaConfig {
    fn default() -> Self {
        Self {
            alpha: 0.3,
            min_data_points: 5,
            max_history: 1000,
        }
    }
}

/// Predictive risk engine
pub struct PredictiveRiskEngine {
    /// Historical risk snapshots per CVE
    history: HashMap<String, Vec<RiskSnapshot>>,
    /// EWMA configuration
    config: EwmaConfig,
}

impl PredictiveRiskEngine {
    pub fn new(config: EwmaConfig) -> Self {
        Self {
            history: HashMap::new(),
            config,
        }
    }

    /// Record a new risk snapshot
    pub fn record(&mut self, cve_id: &str, snapshot: RiskSnapshot) {
        let history = self.history.entry(cve_id.to_string()).or_default();
        history.push(snapshot);

        // Trim history if too large
        if history.len() > self.config.max_history {
            let drain_count = history.len() - self.config.max_history;
            history.drain(0..drain_count);
        }
    }

    /// Predict future risk for a CVE
    pub fn predict(&self, cve_id: &str) -> Option<PredictedRisk> {
        let history = self.history.get(cve_id)?;

        if history.len() < self.config.min_data_points {
            return None;
        }

        // Calculate EWMA for scores
        let scores: Vec<f64> = history.iter().map(|s| s.score as f64).collect();
        let ewma = calculate_ewma(&scores, self.config.alpha);

        // Calculate trend
        let trend = calculate_trend(&scores);

        // Predict future values using linear extrapolation of EWMA
        let current = ewma.last()?;
        let slope = if scores.len() >= 2 {
            let recent_avg: f64 = scores.iter().rev().take(5).sum::<f64>() / 5.0;
            let older_avg: f64 = scores.iter().rev().skip(5).take(5).sum::<f64>() / 5.0;
            (recent_avg - older_avg) / 5.0
        } else {
            0.0
        };

        // Predictions (clamped to 0-10)
        let predicted_1h = (current + slope * 4.0).clamp(0.0, 10.0) as f32;
        let predicted_4h = (current + slope * 16.0).clamp(0.0, 10.0) as f32;
        let predicted_24h = (current + slope * 96.0).clamp(0.0, 10.0) as f32;

        // Confidence based on data quantity and consistency
        let variance = calculate_variance(&scores);
        let confidence =
            ((1.0 / (1.0 + variance)) * (history.len() as f64 / 100.0).min(1.0)) as f32;

        Some(PredictedRisk {
            cve_id: cve_id.to_string(),
            current_score: *current as f32,
            predicted_1h,
            predicted_4h,
            predicted_24h,
            trend,
            confidence,
            data_points: history.len(),
            last_updated: history.last()?.timestamp,
        })
    }

    /// Get all predictions
    pub fn predict_all(&self) -> Vec<PredictedRisk> {
        self.history
            .keys()
            .filter_map(|cve_id| self.predict(cve_id))
            .collect()
    }

    /// Get CVEs with rising trends above threshold
    pub fn get_early_warnings(&self, threshold: f32) -> Vec<PredictedRisk> {
        self.predict_all()
            .into_iter()
            .filter(|p| p.trend == TrendDirection::Rising && p.predicted_4h > threshold)
            .collect()
    }

    /// Clear history for a CVE
    pub fn clear(&mut self, cve_id: &str) {
        self.history.remove(cve_id);
    }

    /// Clear all history
    pub fn clear_all(&mut self) {
        self.history.clear();
    }
}

/// Calculate Exponentially Weighted Moving Average
fn calculate_ewma(values: &[f64], alpha: f64) -> Vec<f64> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut ewma = Vec::with_capacity(values.len());
    ewma.push(values[0]);

    for i in 1..values.len() {
        let prev = ewma[i - 1];
        ewma.push(alpha * values[i] + (1.0 - alpha) * prev);
    }

    ewma
}

/// Calculate trend direction
fn calculate_trend(values: &[f64]) -> TrendDirection {
    if values.len() < 2 {
        return TrendDirection::Stable;
    }

    let recent: f64 = values.iter().rev().take(5).sum::<f64>() / 5.0;
    let older: f64 = values.iter().rev().skip(5).take(5).sum::<f64>() / 5.0;

    let diff = recent - older;
    let threshold = 0.5;

    if diff > threshold {
        TrendDirection::Rising
    } else if diff < -threshold {
        TrendDirection::Falling
    } else {
        TrendDirection::Stable
    }
}

/// Calculate variance
fn calculate_variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance =
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    variance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ewma() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ewma = calculate_ewma(&values, 0.3);

        assert_eq!(ewma.len(), 5);
        assert!((ewma[0] - 1.0).abs() < 0.001);
        // EWMA should be between min and max
        assert!(ewma.iter().all(|&v| v >= 1.0 && v <= 5.0));
    }

    #[test]
    fn test_trend_detection() {
        // Rising trend
        let rising = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(calculate_trend(&rising), TrendDirection::Rising);

        // Falling trend
        let falling = vec![10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
        assert_eq!(calculate_trend(&falling), TrendDirection::Falling);

        // Stable
        let stable = vec![5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0];
        assert_eq!(calculate_trend(&stable), TrendDirection::Stable);
    }

    #[test]
    fn test_predictive_engine() {
        let config = EwmaConfig {
            alpha: 0.3,
            min_data_points: 3,
            max_history: 100,
        };
        let mut engine = PredictiveRiskEngine::new(config);

        // Add some history
        for i in 0..10 {
            engine.record(
                "CVE-2024-1234",
                RiskSnapshot {
                    timestamp: Utc::now(),
                    score: 5.0 + (i as f32 * 0.5),
                    cvss: 7.0,
                    epss: 0.5,
                    kev: false,
                    runtime_signal: 0.3,
                    event_rate: 100.0,
                    network_activity: 50.0,
                },
            );
        }

        let prediction = engine.predict("CVE-2024-1234").unwrap();
        assert!(prediction.confidence > 0.0);
        assert!(prediction.predicted_1h > 0.0);
    }
}
