/**
 * metrics.ts — Observability metrics for RADIUS servers
 *
 * Provides an interface for collecting counters, histograms,
 * and gauges with label support.
 */

export interface MetricLabels {
  [key: string]: string;
}

export interface Metrics {
  increment(name: string, labels?: MetricLabels): void;
  histogram(name: string, value: number, labels?: MetricLabels): void;
  gauge(name: string, value: number, labels?: MetricLabels): void;
}

export interface HistogramData {
  count: number;
  sum: number;
  min: number;
  max: number;
}

export interface MetricsSnapshot {
  counters: Map<string, number>;
  histograms: Map<string, HistogramData>;
  gauges: Map<string, number>;
}

function metricKey(name: string, labels?: MetricLabels): string {
  if (!labels || Object.keys(labels).length === 0) return name;
  const sorted = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b));
  return `${name}{${sorted.map(([k, v]) => `${k}="${v}"`).join(',')}}`;
}

export class DefaultMetrics implements Metrics {
  private counters = new Map<string, number>();
  private histograms = new Map<string, HistogramData>();
  private gauges = new Map<string, number>();

  increment(name: string, labels?: MetricLabels): void {
    const key = metricKey(name, labels);
    this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
  }

  histogram(name: string, value: number, labels?: MetricLabels): void {
    const key = metricKey(name, labels);
    const existing = this.histograms.get(key);
    if (existing) {
      existing.count++;
      existing.sum += value;
      existing.min = Math.min(existing.min, value);
      existing.max = Math.max(existing.max, value);
    } else {
      this.histograms.set(key, { count: 1, sum: value, min: value, max: value });
    }
  }

  gauge(name: string, value: number, labels?: MetricLabels): void {
    const key = metricKey(name, labels);
    this.gauges.set(key, value);
  }

  /** Get a point-in-time snapshot of all metrics. */
  snapshot(): MetricsSnapshot {
    return {
      counters: new Map(this.counters),
      histograms: new Map(this.histograms),
      gauges: new Map(this.gauges),
    };
  }

  /** Reset all metrics. */
  reset(): void {
    this.counters.clear();
    this.histograms.clear();
    this.gauges.clear();
  }

  /** Get a single counter value. */
  getCounter(name: string, labels?: MetricLabels): number {
    return this.counters.get(metricKey(name, labels)) ?? 0;
  }

  /** Get a single gauge value. */
  getGauge(name: string, labels?: MetricLabels): number {
    return this.gauges.get(metricKey(name, labels)) ?? 0;
  }

  /** Get a single histogram. */
  getHistogram(name: string, labels?: MetricLabels): HistogramData | undefined {
    return this.histograms.get(metricKey(name, labels));
  }
}

export class NullMetrics implements Metrics {
  increment(): void {}
  histogram(): void {}
  gauge(): void {}
}
