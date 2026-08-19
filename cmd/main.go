// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	goflag "flag"
	"os"

	"github.com/ironcore-dev/pool-lifecycle-controller/internal/client/index"
	flag "github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	computev1alpha1 "github.com/ironcore-dev/ironcore/api/compute/v1alpha1"
	"github.com/ironcore-dev/ironcore/utils/client/config"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"

	ironcoreconfig "github.com/ironcore-dev/pool-lifecycle-controller/internal/client/config"
	"github.com/ironcore-dev/pool-lifecycle-controller/internal/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	scheme         = runtime.NewScheme()
	ironCoreScheme = runtime.NewScheme()
	setupLog       = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(clusterv1.AddToScheme(scheme))

	utilruntime.Must(clientgoscheme.AddToScheme(ironCoreScheme))
	utilruntime.Must(computev1alpha1.AddToScheme(ironCoreScheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var capiMachineSelector string
	var localCfgOpts config.GetConfigOptions
	var ironCoreCfgOpts config.GetConfigOptions
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&capiMachineSelector, "capi-machine-selector", "",
		"Label selector restricting which CAPI Machines are managed (e.g. 'pool=worker,tier!=spot'). Empty selects all.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	localCfgOpts.BindFlags(flag.CommandLine)
	ironCoreCfgOpts.BindFlags(flag.CommandLine, config.WithNamePrefix("ironcore-"))

	opts := zap.Options{
		Development: true,
	}
	goFlags := goflag.NewFlagSet(os.Args[0], goflag.ExitOnError)
	opts.BindFlags(goFlags)
	flag.CommandLine.AddGoFlagSet(goFlags)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	ctx := ctrl.SetupSignalHandler()

	ironCoreConfigured := ironCoreCfgOpts.Kubeconfig != "" ||
		ironCoreCfgOpts.KubeconfigSecretName != "" ||
		ironCoreCfgOpts.BootstrapKubeconfig != ""
	if !ironCoreConfigured {
		setupLog.Error(nil, "Must specify the IronCore cluster config via "+
			"--ironcore-kubeconfig, --ironcore-kubeconfig-secret-name or --ironcore-bootstrap-kubeconfig")
		os.Exit(1)
	}

	localGetter, err := config.NewBrokerGetter(config.GetterOptions{Name: "management"})
	if err != nil {
		setupLog.Error(err, "Failed to create config getter")
		os.Exit(1)
	}
	cfg, err := localGetter.GetConfig(ctx, &localCfgOpts)
	if err != nil {
		setupLog.Error(err, "Failed to load kubeconfig")
		os.Exit(1)
	}

	ironCoreConfig, ironCoreCfgCtrl, err := ironcoreconfig.GetConfig(ctx, &ironCoreCfgOpts)
	if err != nil {
		setupLog.Error(err, "Failed to load IronCore kubeconfig")
		os.Exit(1)
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "083c9ee4.ironcore.dev",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	ironCoreCluster, err := cluster.New(ironCoreConfig, func(o *cluster.Options) {
		o.Scheme = ironCoreScheme
	})
	if err != nil {
		setupLog.Error(err, "Failed to create IronCore cluster")
		os.Exit(1)
	}
	if err := mgr.Add(ironCoreCluster); err != nil {
		setupLog.Error(err, "Failed to add IronCore cluster to manager")
		os.Exit(1)
	}

	if err := config.SetupControllerWithManager(mgr, ironCoreCfgCtrl); err != nil {
		setupLog.Error(err, "Failed to set up IronCore config controller")
		os.Exit(1)
	}

	if err := index.SetupCAPIMachineNodeRefNameFieldIndexer(ctx, mgr.GetFieldIndexer()); err != nil {
		setupLog.Error(err, "Failed to set up field indexer", "field", index.CAPIMachineNodeRefNameField)
		os.Exit(1)
	}
	if err := index.SetupMachinePoolRefNameFieldIndexer(ctx, ironCoreCluster.GetFieldIndexer()); err != nil {
		setupLog.Error(err, "Failed to set up field indexer", "field", "spec.machinePoolRef.name")
		os.Exit(1)
	}

	machineSelector, err := labels.Parse(capiMachineSelector)
	if err != nil {
		setupLog.Error(err, "Failed to parse CAPI Machine selector", "selector", capiMachineSelector)
		os.Exit(1)
	}

	if err := (&controllers.MachinePoolLifecycleReconciler{
		Client:              mgr.GetClient(),
		IronCoreClient:      ironCoreCluster.GetClient(),
		CAPIMachineSelector: machineSelector,
	}).SetupWithManager(mgr, ironCoreCluster.GetCache()); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "MachinePoolLifecycle")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
