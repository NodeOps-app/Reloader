package common

import (
    "strconv"
    "time"
	"github.com/stakater/Reloader/internal/pkg/constants"
	"github.com/stakater/Reloader/internal/pkg/options"
	"github.com/stakater/Reloader/internal/pkg/util"
	v1 "k8s.io/api/core/v1"
)

// Config contains rolling upgrade configuration parameters
type Config struct {
	Namespace           string
	ResourceName        string
	ResourceAnnotations map[string]string
	Annotation          string
	TypedAutoAnnotation string
	SHAValue            string
	Type                string
	Labels              map[string]string
}

// GetConfigmapConfig provides utility config for configmap
func GetConfigmapConfig(configmap *v1.ConfigMap) Config {
	return Config{
		Namespace:           configmap.Namespace,
		ResourceName:        configmap.Name,
		ResourceAnnotations: configmap.Annotations,
		Annotation:          options.ConfigmapUpdateOnChangeAnnotation,
		TypedAutoAnnotation: options.ConfigmapReloaderAutoAnnotation,
		SHAValue:            util.GetSHAfromConfigmap(configmap),
		Type:                constants.ConfigmapEnvVarPostfix,
		Labels:              configmap.Labels,
	}
}

// GetSecretConfig provides utility config for secret
func GetSecretConfig(secret *v1.Secret) Config {
	return Config{
		Namespace:           secret.Namespace,
		ResourceName:        secret.Name,
		ResourceAnnotations: secret.Annotations,
		Annotation:          options.SecretUpdateOnChangeAnnotation,
		TypedAutoAnnotation: options.SecretReloaderAutoAnnotation,
		SHAValue:            util.GetSHAfromSecret(secret.Data),
		Type:                constants.SecretEnvVarPostfix,
		Labels:              secret.Labels,
	}
}

// GetVaultConfig provides utility config for an external Vault path rotation trigger
// The resourceName should match the value provided in the workload annotation defined by VaultUpdateOnChangeAnnotation
// SHAValue can be any changing token (e.g., version from Vault); if empty, current timestamp is used
func GetVaultConfig(namespace string, resourceName string, version string) Config {
	sha := version
	if sha == "" {
		sha = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return Config{
		Namespace:           namespace,
		ResourceName:        resourceName,
		ResourceAnnotations: map[string]string{},
		Annotation:          options.VaultUpdateOnChangeAnnotation,
		TypedAutoAnnotation: "",
		SHAValue:            sha,
		Type:                constants.SecretEnvVarPostfix,
		Labels:              map[string]string{},
	}
}
