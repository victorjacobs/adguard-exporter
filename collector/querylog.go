package collector

import (
	"fmt"
	"math"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	processingTimeMillisecondBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	processingTimeSecondBuckets      = []float64{0.000005, 0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01}
	queryDetailsBuckets              = []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90}
)

type histogramKey struct {
	client   string
	upstream string
}

type detailHistogramKey struct {
	clientName string
	protocol   string
	reason     string
	status     string
	upstream   string
	user       string
}

type detailKey struct {
	client     string
	clientName string
	domain     string
	protocol   string
	reason     string
	status     string
	queryType  string
	upstream   string
}

type histogramData struct {
	buckets map[float64]uint64
	sum     float64
	count   uint64
}

func newHistogramData(bounds []float64) *histogramData {
	buckets := make(map[float64]uint64, len(bounds))
	for _, bound := range bounds {
		buckets[bound] = 0
	}

	return &histogramData{buckets: buckets}
}

func (h *histogramData) observe(value float64, bounds []float64) {
	for _, bound := range bounds {
		if value <= bound {
			h.buckets[bound]++
		}
	}

	h.sum += value
	h.count++
}

func histogramFor[K comparable](histograms map[K]*histogramData, key K, bounds []float64) *histogramData {
	histogram, exists := histograms[key]
	if !exists {
		histogram = newHistogramData(bounds)
		histograms[key] = histogram
	}

	return histogram
}

func (c *Collector) collectQueryLog(ch chan<- prometheus.Metric) error {
	queryLog, err := c.client.GetQueryLog()
	if err != nil {
		return err
	}

	millisecondHistograms := make(map[histogramKey]*histogramData)
	secondHistograms := make(map[histogramKey]*histogramData)
	detailHistograms := make(map[detailHistogramKey]*histogramData)
	detailCounts := make(map[detailKey]uint64)

	var firstInvalidElapsed error
	invalidElapsedCount := 0

	for _, entry := range queryLog.Data {
		elapsedMilliseconds, err := parseElapsedMilliseconds(entry.ElapsedMs)
		if err != nil {
			invalidElapsedCount++
			if firstInvalidElapsed == nil {
				firstInvalidElapsed = err
			}

			continue
		}

		status := entry.Status
		if status == "" {
			status = entry.Reason
		}

		protocol := entry.ClientProtocol
		if protocol == "" {
			protocol = "plain"
		}

		detail := detailKey{
			client:     entry.Client,
			clientName: entry.ClientInfo.Name,
			domain:     entry.Question.Name,
			protocol:   protocol,
			reason:     entry.Reason,
			status:     status,
			queryType:  entry.Question.Type,
			upstream:   entry.Upstream,
		}
		detailCounts[detail]++

		histogram := histogramKey{client: entry.Client, upstream: entry.Upstream}
		histogramFor(millisecondHistograms, histogram, processingTimeMillisecondBuckets).
			observe(elapsedMilliseconds, processingTimeMillisecondBuckets)
		histogramFor(secondHistograms, histogram, processingTimeSecondBuckets).
			observe(elapsedMilliseconds/1000, processingTimeSecondBuckets)

		detailHistogram := detailHistogramKey{
			clientName: entry.ClientInfo.Name,
			protocol:   protocol,
			reason:     entry.Reason,
			status:     status,
			upstream:   entry.Upstream,
			user:       entry.Client,
		}
		histogramFor(detailHistograms, detailHistogram, queryDetailsBuckets).
			observe(elapsedMilliseconds, queryDetailsBuckets)
	}

	for detail, count := range detailCounts {
		ch <- prometheus.MustNewConstMetric(
			c.metrics.queriesDetails,
			prometheus.GaugeValue,
			float64(count),
			detail.client,
			detail.clientName,
			detail.domain,
			detail.protocol,
			detail.reason,
			c.server,
			detail.status,
			detail.queryType,
			detail.upstream,
		)
	}

	for key, histogram := range millisecondHistograms {
		ch <- prometheus.MustNewConstHistogram(
			c.metrics.processingTimeMilliseconds,
			histogram.count,
			histogram.sum,
			histogram.buckets,
			key.client,
			c.server,
			key.upstream,
		)
	}

	for key, histogram := range secondHistograms {
		ch <- prometheus.MustNewConstHistogram(
			c.metrics.processingTimeSeconds,
			histogram.count,
			histogram.sum,
			histogram.buckets,
			key.client,
			c.server,
			key.upstream,
		)
	}

	for key, histogram := range detailHistograms {
		ch <- prometheus.MustNewConstHistogram(
			c.metrics.queriesDetailsHistogram,
			histogram.count,
			histogram.sum,
			histogram.buckets,
			key.clientName,
			key.protocol,
			key.reason,
			c.server,
			key.status,
			key.upstream,
			key.user,
		)
	}

	if invalidElapsedCount > 0 {
		return fmt.Errorf(
			"skip %d query log entries with invalid elapsed time (first error: %w)",
			invalidElapsedCount,
			firstInvalidElapsed,
		)
	}

	return nil
}

func parseElapsedMilliseconds(value string) (float64, error) {
	elapsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", value, err)
	}
	if elapsed < 0 || math.IsInf(elapsed, 0) || math.IsNaN(elapsed) {
		return 0, fmt.Errorf("parse %q: value must be a finite non-negative number", value)
	}

	return elapsed, nil
}
