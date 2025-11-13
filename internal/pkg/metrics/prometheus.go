package metrics

import (
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collectors struct {
	Reloaded                 *prometheus.CounterVec
	ReloadedByNamespace      *prometheus.CounterVec
	VaultTriggers            *prometheus.CounterVec
	VaultTriggersByNamespace *prometheus.CounterVec
}

func NewCollectors() Collectors {
	reloaded := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "reloader",
			Name:      "reload_executed_total",
			Help:      "Counter of reloads executed by Reloader.",
		},
		[]string{
			"success",
		},
	)

	//set 0 as default value
	reloaded.With(prometheus.Labels{"success": "true"}).Add(0)
	reloaded.With(prometheus.Labels{"success": "false"}).Add(0)

	reloaded_by_namespace := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "reloader",
			Name:      "reload_executed_total_by_namespace",
			Help:      "Counter of reloads executed by Reloader by namespace.",
		},
		[]string{
			"success",
			"namespace",
		},
	)

	vaultTriggers := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "reloader",
			Name:      "vault_triggers_total",
			Help:      "Counter of Vault rotation triggers received by Reloader.",
		},
		[]string{
			"success",
		},
	)
	// set 0 as default values
	vaultTriggers.With(prometheus.Labels{"success": "true"}).Add(0)
	vaultTriggers.With(prometheus.Labels{"success": "false"}).Add(0)

	vaultTriggersByNamespace := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "reloader",
			Name:      "vault_triggers_total_by_namespace",
			Help:      "Counter of Vault rotation triggers received by Reloader by namespace.",
		},
		[]string{
			"success",
			"namespace",
		},
	)
	return Collectors{
		Reloaded:                 reloaded,
		ReloadedByNamespace:      reloaded_by_namespace,
		VaultTriggers:            vaultTriggers,
		VaultTriggersByNamespace: vaultTriggersByNamespace,
	}
}

func SetupPrometheusEndpoint() Collectors {
	collectors := NewCollectors()
	prometheus.MustRegister(collectors.Reloaded)
	prometheus.MustRegister(collectors.VaultTriggers)

	if os.Getenv("METRICS_COUNT_BY_NAMESPACE") == "enabled" {
		prometheus.MustRegister(collectors.ReloadedByNamespace)
		prometheus.MustRegister(collectors.VaultTriggersByNamespace)
	}

	http.Handle("/metrics", promhttp.Handler())

	return collectors
}
