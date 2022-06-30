package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhmutating "github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/net"
)

const containerName = "apifirewall"
const volumeNameExLogs = "firewall-logs"
const volumeNameTLS = "certs-volume"

type InjectedSecret struct {
	EnvName    string
	SecretName string
	SecretKey  string
}

type Configuration struct {
	// ServerDefaults
	DockerImage string
	MaxCPU      string
	MaxMem      string
	PlatformUrl string

	// mandatory
	ContainerPort   string `json:"xliic.com/container-port"`
	ProtectionToken string `json:"xliic.com/protection-token"`
	TargetUrl       string `json:"xliic.com/target-url"`
	ServerName      string `json:"xliic.com/server-name"`

	// mandatory if SSL is enabled
	TlsSecretName string `json:"xliic.com/tls-secret-name"`

	// optional
	HttpOnly           string `json:"xliic.com/http-only"`
	EnvConfigMap       string `json:"xliic.com/env-configmap"`
	Debug              string `json:"xliic.com/debug"`
	LogToVolume        string `json:"xliic.com/log-to-volume"`
	InjectSecretEnvJwk string `json:"xliic.com/inject-secret-env-jwk"`

	// later filled by readConfiguration()
	InjectedSecrets []InjectedSecret
}

type ServerDefaults struct {
	MaxMem   string
	MaxCPU   string
	Image    string
	Platform string
}

func CreateServer(defaults *ServerDefaults) (*http.Server, error) {
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	mutator := kwhmutating.MutatorFunc(func(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhmutating.MutatorResult, error) {
		return sidecarInjectMutator(logger, obj, defaults)
	})

	config := kwhmutating.WebhookConfig{
		ID:      "xliicSidecarInjector",
		Mutator: mutator,
		Logger:  logger,
		Obj:     &corev1.Pod{},
	}

	webhook, err := kwhmutating.NewWebhook(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook: %s", err)
	}

	handler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{Webhook: webhook, Logger: logger})
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook handler: %s", err)
	}

	server := http.Server{Addr: ":8080", Handler: handler}

	return &server, nil
}

func findContainer(name string, pod *corev1.Pod) *corev1.Container {
	for _, container := range pod.Spec.Containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func sidecarInjectMutator(logger kwhlog.Logger, obj metav1.Object, defaults *ServerDefaults) (*kwhmutating.MutatorResult, error) {
	pod, ok := obj.(*corev1.Pod)

	if !ok {
		return nil, fmt.Errorf("failed to get pod object")
	}

	injected := findContainer(containerName, pod)
	if injected != nil {
		// already injected, make no changes
		return &kwhmutating.MutatorResult{}, nil
	}

	configuration, err := readConfiguration(pod, defaults)
	if err != nil {
		return nil, fmt.Errorf("failed to read config from annotations: %s", err)
	}

	sidecar, err := createSidecar(configuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create sidecar container: %s", err)
	}

	logger.Infof("Command : %s", sidecar.Command)
	logger.Infof("Args : %s", sidecar.Args)

	if configuration.HttpOnly != "enabled" {
		logger.Infof("Configuring Firewall with TLS")
		pod.Spec.Volumes = append(pod.Spec.Volumes, getVolumeForTLS(configuration.TlsSecretName))
	}

	if configuration.LogToVolume != "" {
		logger.Infof("Configuring External Logging")
		pod.Spec.Volumes = append(pod.Spec.Volumes, getVolumeForExtLogs(configuration.LogToVolume))
	}

	pod.Spec.Containers = append(pod.Spec.Containers, *sidecar)

	return &kwhmutating.MutatorResult{}, nil
}

func createSidecar(configuration *Configuration) (*corev1.Container, error) {
	containerPort, err := net.ParsePort(configuration.ContainerPort, false)
	if err != nil {
		return nil, fmt.Errorf("failed to read xliic.com/container-port: %s", err)
	}

	//add our sidecar
	sidecar := corev1.Container{
		ImagePullPolicy: corev1.PullAlways,
		Name:            containerName,
		Image:           configuration.DockerImage,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("100Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(configuration.MaxCPU),
				corev1.ResourceMemory: resource.MustParse(configuration.MaxMem),
			},
		},
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt(8880), Path: "/hc"}},
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt(8880), Path: "/hc"}},
		},
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: int32(containerPort),
			},
		},
		Args: []string{
			"-platform",
			configuration.PlatformUrl,
		},
		Command: []string{
			"/bin/squire",
		},
		Env: []corev1.EnvVar{
			{
				Name: "GUARDIAN_NODE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.nodeName",
					},
				},
			},
			{
				Name: "GUARDIAN_INSTANCE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.name",
					},
				},
			},
			{
				Name: "GUARDIAN_INSTANCE_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
			{
				Name: "GUARDIAN_INSTANCE_IP",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "status.podIP",
					},
				},
			},
			{
				Name: "GUARDIAN_INSTANCE_SERVICE_ACCOUNT",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "spec.serviceAccountName",
					},
				},
			},
			{
				Name: "PROTECTION_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key:                  "PROTECTION_TOKEN",
						LocalObjectReference: corev1.LocalObjectReference{Name: configuration.ProtectionToken},
					},
				},
			},
			{
				Name:  "TARGET_URL",
				Value: configuration.TargetUrl,
			},
			{
				Name:  "SERVER_NAME",
				Value: configuration.ServerName,
			},
			{
				Name:  "LISTEN_PORT",
				Value: fmt.Sprintf("%d", containerPort),
			},
		},
	}

	if configuration.HttpOnly != "enabled" {
		sidecar.Env = append(sidecar.Env, corev1.EnvVar{
			Name:  "LISTEN_SSL_CERT",
			Value: "tls.crt",
		})
		sidecar.Env = append(sidecar.Env, corev1.EnvVar{
			Name:  "LISTEN_SSL_KEY",
			Value: "tls.key",
		})
		sidecar.VolumeMounts = append(sidecar.VolumeMounts, corev1.VolumeMount{
			Name:      volumeNameTLS,
			ReadOnly:  true,
			MountPath: "/opt/guardian/conf/ssl",
		})
	} else {
		sidecar.Env = append(sidecar.Env, corev1.EnvVar{
			Name:  "LISTEN_NO_TLS",
			Value: "ENABLED",
		})
	}

	if configuration.LogToVolume != "" {
		sidecar.VolumeMounts = append(sidecar.VolumeMounts, corev1.VolumeMount{
			Name:      volumeNameExLogs,
			ReadOnly:  false,
			MountPath: "/opt/guardian/logs",
		})
	}

	if configuration.EnvConfigMap != "" {
		sidecar.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: configuration.EnvConfigMap,
			}}}}
	}

	for _, injectedSecret := range configuration.InjectedSecrets {
		sidecar.Env = append(sidecar.Env, getEnvVarForSecret(injectedSecret))
	}

	if configuration.Debug == "enabled" {
		sidecar.Args = append(sidecar.Args, "-debug")
	}

	return &sidecar, nil

}

func readConfiguration(pod *corev1.Pod, defaults *ServerDefaults) (*Configuration, error) {
	configuration := Configuration{}

	bytes, err := json.Marshal(pod.Annotations)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bytes, &configuration)
	if err != nil {
		return nil, err
	}

	configuration.DockerImage = defaults.Image
	configuration.MaxCPU = defaults.MaxCPU
	configuration.MaxMem = defaults.MaxMem
	configuration.PlatformUrl = defaults.Platform

	if configuration.ProtectionToken == "" {
		return nil, fmt.Errorf("mandatory annotation is missing: %s", "xliic.com/protection-token")
	}

	if configuration.TargetUrl == "" {
		return nil, fmt.Errorf("mandatory annotation is missing: %s", "xliic.com/target-url")
	}

	if configuration.ContainerPort == "" {
		return nil, fmt.Errorf("mandatory annotation is missing: %s", "xliic.com/container-port")
	}

	if configuration.ServerName == "" {
		return nil, fmt.Errorf("mandatory annotation is missing: %s", "xliic.com/server-name")
	}

	if configuration.HttpOnly != "enabled" && configuration.TlsSecretName == "" {
		return nil, fmt.Errorf("SSL is enabled but %s annotation is missing", "xliic.com/tls-secret-name")
	}

	if configuration.InjectSecretEnvJwk != "" {
		parts := strings.Split(configuration.InjectSecretEnvJwk, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid value for %s must be secret name and secret key separated by '/'",
				"xliic.com/inject-secret-env-jwk")
		}
		configuration.InjectedSecrets = append(configuration.InjectedSecrets,
			InjectedSecret{EnvName: "JWK", SecretName: parts[0], SecretKey: parts[1]})
	}

	return &configuration, nil
}

func getVolumeForExtLogs(claimName string) corev1.Volume {
	return corev1.Volume{
		Name: volumeNameExLogs,
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: claimName,
			},
		},
	}
}

func getVolumeForTLS(name string) corev1.Volume {
	return corev1.Volume{
		Name: volumeNameTLS,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: name,
			},
		},
	}
}

func getEnvVarForSecret(injectedSecret InjectedSecret) corev1.EnvVar {
	return corev1.EnvVar{
		Name: injectedSecret.EnvName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				Key:                  injectedSecret.SecretKey,
				LocalObjectReference: corev1.LocalObjectReference{Name: injectedSecret.SecretName},
			},
		},
	}
}
