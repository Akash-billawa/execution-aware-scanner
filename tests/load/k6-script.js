import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const healthLatency = new Trend('health_latency');
const metricsLatency = new Trend('metrics_latency');

// Test configuration
export const options = {
  stages: [
    // Ramp up
    { duration: '30s', target: 10 },
    // Stay at 10 VUs for 2 minutes
    { duration: '2m', target: 10 },
    // Ramp up to 50 VUs
    { duration: '30s', target: 50 },
    // Stay at 50 VUs for 5 minutes
    { duration: '5m', target: 50 },
    // Ramp down
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    errors: ['rate<0.1'],
    health_latency: ['p(95)<100'],
    metrics_latency: ['p(95)<200'],
  },
};

const BASE_URL = __ENV.SCANNER_URL || 'http://localhost:9898';

export default function () {
  // Health check
  const healthStart = Date.now();
  const healthRes = http.get(`${BASE_URL}/health`);
  healthLatency.add(Date.now() - healthStart);

  check(healthRes, {
    'health status 200': (r) => r.status === 200,
    'health response ok': (r) => r.body && r.body.length > 0,
  }) || errorRate.add(1);

  // Metrics endpoint
  const metricsStart = Date.now();
  const metricsRes = http.get(`${BASE_URL}/metrics`);
  metricsLatency.add(Date.now() - metricsStart);

  check(metricsRes, {
    'metrics status 200': (r) => r.status === 200,
    'metrics has content': (r) => r.body && r.body.includes('scanner_'),
  }) || errorRate.add(1);

  // API endpoints
  const apiRes = http.get(`${BASE_URL}/api/v1/stats`);
  check(apiRes, {
    'api stats status 200': (r) => r.status === 200,
  }) || errorRate.add(1);

  // Findings endpoint
  const findingsRes = http.get(`${BASE_URL}/api/v1/findings`);
  check(findingsRes, {
    'findings status 200': (r) => r.status === 200,
  }) || errorRate.add(1);

  sleep(0.1);
}

export function handleSummary(data) {
  return {
    'load-test-results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, opts) {
  const { metrics } = data;
  let summary = '\n=== Load Test Results ===\n\n';

  for (const [name, metric] of Object.entries(metrics)) {
    if (metric.values) {
      summary += `${name}:\n`;
      for (const [key, value] of Object.entries(metric.values)) {
        summary += `  ${key}: ${typeof value === 'number' ? value.toFixed(2) : value}\n`;
      }
    }
  }

  return summary;
}
