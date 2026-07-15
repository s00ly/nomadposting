package egress

import (
	"context"
	"fmt"
	"time"
)

// ProbeReport contains only normalized booleans. Exit IPs, DNS answers, and
// other network metadata must not enter controller state or logs.
type ProbeReport struct {
	EndpointID    EndpointID
	CheckedAt     time.Time
	Reachable     bool
	StaticIPMatch bool
	CountryMatch  bool
	DNSLeak       bool
	RouteLeak     bool
	TLSValid      bool
}

func (r *Registry) ApplyProbe(report ProbeReport) error {
	if report.CheckedAt.IsZero() {
		return fmt.Errorf("probe timestamp is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[report.EndpointID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEndpoint, report.EndpointID)
	}
	record.Health.CheckedAt = report.CheckedAt.UTC()
	hardFailure := !report.StaticIPMatch || !report.CountryMatch || report.DNSLeak || report.RouteLeak || !report.TLSValid
	if hardFailure {
		record.Health.Healthy = false
		record.Health.Failures++
		record.Health.Quarantined = true
	} else if !report.Reachable {
		record.Health.Healthy = false
		record.Health.Failures++
		if record.Health.Failures >= 3 {
			record.Health.Quarantined = true
		}
	} else if !record.Health.Quarantined {
		record.Health.Healthy = true
		record.Health.Failures = 0
	}
	r.records[report.EndpointID] = record
	return nil
}

type EndpointProber interface {
	Probe(context.Context, Endpoint) (ProbeReport, error)
}

type HealthMonitor struct {
	Registry *Registry
	Prober   EndpointProber
	Interval time.Duration
}

// Run checks every registered endpoint once immediately and then on the
// configured interval. Probe errors count as ordinary reachability failures;
// normalized leak or identity mismatches in reports quarantine immediately.
func (m HealthMonitor) Run(ctx context.Context) error {
	if m.Registry == nil || m.Prober == nil {
		return fmt.Errorf("registry and prober are required")
	}
	if m.Interval != 60*time.Second {
		return fmt.Errorf("health interval must be exactly 60 seconds")
	}
	for {
		m.probeAll(ctx)
		timer := time.NewTimer(m.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m HealthMonitor) probeAll(ctx context.Context) {
	for _, item := range m.Registry.Snapshot() {
		report, err := m.Prober.Probe(ctx, item.Endpoint)
		if err != nil {
			_ = m.Registry.MarkProbe(item.Endpoint.ID, false, time.Now().UTC())
			continue
		}
		report.EndpointID = item.Endpoint.ID
		_ = m.Registry.ApplyProbe(report)
	}
}
