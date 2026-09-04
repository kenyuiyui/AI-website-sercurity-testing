/**
 * stats.js — Wilson score interval 計算,用於評估「命中率」「誤判率」的統計可信度。
 *
 * 為什麼用 Wilson 而不是最簡單的常態近似(p ± z*sqrt(p(1-p)/n)):
 * 常態近似在 n 小或 p 接近 0/1 時會給出不合理的結果(例如信賴區間跑到負數,
 * 或 0 次命中時區間寬度算成 0)。Wilson score interval 在小樣本時依然穩定,
 * 是二項比例信賴區間的標準做法之一(在 R 的 binom.test 等統計套件裡常見)。
 */

/**
 * 計算 Wilson score interval。
 * @param {number} hits - 命中次數
 * @param {number} n - 總樣本數
 * @param {number} z - 信心水準對應的 z 值,預設 1.96(95% 信心水準)
 * @returns {{point: number, lower: number, upper: number, halfWidthPct: number}}
 */
function wilsonInterval(hits, n, z = 1.96) {
  if (n === 0) {
    return { point: 0, lower: 0, upper: 1, halfWidthPct: 100 };
  }
  const p = hits / n;
  const denom = 1 + (z * z) / n;
  const center = (p + (z * z) / (2 * n)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / denom;
  const lower = Math.max(0, center - margin);
  const upper = Math.min(1, center + margin);
  return {
    point: p,
    lower,
    upper,
    halfWidthPct: ((upper - lower) / 2) * 100
  };
}

/**
 * 給定目前的命中率估計與目標半寬(百分點),回推大約還需要多少總樣本數才能達標。
 * 用二分搜尋法反推,因為 Wilson interval 沒有簡單的反函式。
 * @param {number} assumedRate - 假設的真實命中率(0~1),抓目前觀察到的比例
 * @param {number} targetHalfWidthPct - 目標半寬,例如 5 代表 ±5個百分點
 * @returns {number} 估計所需的總樣本數
 */
function estimateRequiredN(assumedRate, targetHalfWidthPct) {
  let lo = 2, hi = 5000;
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    const hits = Math.round(mid * assumedRate);
    const { halfWidthPct } = wilsonInterval(hits, mid);
    if (halfWidthPct <= targetHalfWidthPct) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }
  return lo;
}

module.exports = { wilsonInterval, estimateRequiredN };
