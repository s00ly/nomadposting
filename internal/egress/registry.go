package egress

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type endpointRecord struct {
	Endpoint Endpoint
	Health   Health
}

// Registry is the sole resolver of endpoint IDs accepted by the broker.
type Registry struct {
	mu      sync.RWMutex
	records map[EndpointID]endpointRecord
}

func NewRegistry(endpoints []Endpoint) (*Registry, error) {
	r := &Registry{records: make(map[EndpointID]endpointRecord, len(endpoints))}
	for _, endpoint := range endpoints {
		if err := endpoint.Validate(); err != nil {
			return nil, err
		}
		if _, exists := r.records[endpoint.ID]; exists {
			return nil, fmt.Errorf("duplicate endpoint ID %q", endpoint.ID)
		}
		r.records[endpoint.ID] = endpointRecord{Endpoint: endpoint}
	}
	if len(r.records) == 0 {
		return nil, fmt.Errorf("endpoint registry cannot be empty")
	}
	return r, nil
}

func (r *Registry) Resolve(id EndpointID) (Endpoint, Health, error) {
	if err := id.Validate(); err != nil {
		return Endpoint{}, Health{}, fmt.Errorf("%w: %v", ErrUnknownEndpoint, err)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, ok := r.records[id]
	if !ok {
		return Endpoint{}, Health{}, fmt.Errorf("%w: %q", ErrUnknownEndpoint, id)
	}
	return record.Endpoint, record.Health, nil
}

func (r *Registry) SetHealth(id EndpointID, health Health) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEndpoint, id)
	}
	record.Health = health
	r.records[id] = record
	return nil
}

func (r *Registry) MarkProbe(id EndpointID, healthy bool, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEndpoint, id)
	}
	record.Health.CheckedAt = now.UTC()
	record.Health.Healthy = healthy
	if healthy {
		record.Health.Failures = 0
	} else {
		record.Health.Failures++
		if record.Health.Failures >= 3 {
			record.Health.Quarantined = true
		}
	}
	r.records[id] = record
	return nil
}

func (r *Registry) Snapshot() []struct {
	Endpoint Endpoint `json:"endpoint"`
	Health   Health   `json:"health"`
} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]struct {
		Endpoint Endpoint `json:"endpoint"`
		Health   Health   `json:"health"`
	}, 0, len(r.records))
	for _, record := range r.records {
		result = append(result, struct {
			Endpoint Endpoint `json:"endpoint"`
			Health   Health   `json:"health"`
		}{record.Endpoint, record.Health})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Endpoint.ID < result[j].Endpoint.ID })
	return result
}
