package deployment

import (
	"strings"

	"github.com/securesign/operator/api/v1alpha1"
	cryptoutil "github.com/securesign/operator/internal/utils/crypto"
	"github.com/securesign/operator/internal/utils/kubernetes"
	"github.com/securesign/operator/internal/utils/kubernetes/ensure"
	tlsensure "github.com/securesign/operator/internal/utils/tls/ensure"
	v1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

func Proxy(noProxy ...string) func(*v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		ensure.SetProxyEnvs(dp.Spec.Template.Spec.Containers, noProxy...)
		return nil
	}
}

// TrustedCA mount config map with trusted CA bundle to all deployment's containers.
func TrustedCA(lor *v1alpha1.LocalObjectReference, containerName string, moreNames ...string) func(dp *v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		return tlsensure.TrustedCA(lor, containerName, moreNames...)(&dp.Spec.Template)
	}
}

// TLS mount secret with tls cert to all deployment's containers.
func TLS(tls v1alpha1.TLS, containerNames ...string) func(dp *v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		return tlsensure.TLS(tls, containerNames...)(&dp.Spec.Template)
	}
}

func PodRequirements(requirements v1alpha1.PodRequirements, containerName string) func(*v1.Deployment) error {
	return func(deployment *v1.Deployment) error {
		deployment.Spec.Replicas = requirements.Replicas

		template := &deployment.Spec.Template
		template.Spec.Affinity = requirements.Affinity
		template.Spec.Tolerations = requirements.Tolerations

		container := kubernetes.FindContainerByNameOrCreate(&template.Spec, containerName)
		if requirements.Resources != nil {
			container.Resources = *requirements.Resources
		} else {
			container.Resources = core.ResourceRequirements{}
		}
		return nil
	}
}

func PodSecurityContext() func(deployment *v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		return ensure.PodSecurityContext(&dp.Spec.Template.Spec)
	}
}

func GoDebugFIPSOnly(containerNames ...string) func(deployment *v1.Deployment) error {
	return func(dp *v1.Deployment) error {
		if !cryptoutil.FIPSEnabled {
			return nil
		}

		spec := &dp.Spec.Template.Spec

		if len(containerNames) == 0 {
			for i := range spec.InitContainers {
				ensureGoDebugFIPSOnly(&spec.InitContainers[i])
			}
			for i := range spec.Containers {
				ensureGoDebugFIPSOnly(&spec.Containers[i])
			}
			return nil
		}

		nameSet := make(map[string]struct{}, len(containerNames))
		for _, name := range containerNames {
			nameSet[name] = struct{}{}
		}

		for i := range spec.InitContainers {
			if _, ok := nameSet[spec.InitContainers[i].Name]; ok {
				ensureGoDebugFIPSOnly(&spec.InitContainers[i])
			}
		}
		for i := range spec.Containers {
			if _, ok := nameSet[spec.Containers[i].Name]; ok {
				ensureGoDebugFIPSOnly(&spec.Containers[i])
			}
		}

		return nil
	}
}

func ensureGoDebugFIPSOnly(container *core.Container) {
	env := kubernetes.FindEnvByNameOrCreate(container, "GODEBUG")
	env.ValueFrom = nil
	env.Value = mergeGoDebugValue(env.Value)
}

func mergeGoDebugValue(existing string) string {
	parts := strings.Split(existing, ",")
	out := make([]string, 0, len(parts)+1)
	out = append(out, "fips140=only")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "fips140=") {
			continue
		}
		if part == "fips140=only" {
			continue
		}
		out = append(out, part)
	}

	return strings.Join(out, ",")
}
