/*
Copyright 2024 Drivenets

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	cdnosv1 "github.com/drivenets/cdnos-controller/api/v1"
	"github.com/drivenets/cdnos-controller/internal/controller"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cdnosv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var maxConcurrentReconciles int
	var kubeQPS float64
	var kubeBurst int
	healDefaults := controller.DefaultMeshnetHealConfig()
	var meshnetHealEnabled bool
	var meshnetHealGrace time.Duration
	var meshnetHealMaxAttempts int
	var meshnetHealBackoff time.Duration
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8084", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8085", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 20,
		"Maximum number of concurrent Reconciles which can be run for the Cdnos controller.")
	flag.Float64Var(&kubeQPS, "kube-api-qps", 100,
		"Maximum queries-per-second to the Kubernetes API server (client-side rate limit).")
	flag.IntVar(&kubeBurst, "kube-api-burst", 200,
		"Maximum burst for throttle to the Kubernetes API server.")
	flag.BoolVar(&meshnetHealEnabled, "meshnet-heal-enabled", healDefaults.Enabled,
		"Detect Cdnos pods that meshnet never wired (the new-node CNI race, AR-65093) and heal them by recreating the pod.")
	flag.DurationVar(&meshnetHealGrace, "meshnet-heal-grace", healDefaults.GracePeriod,
		"How long a pod must be Running-but-under-wired before meshnet detect-and-heal recreates it.")
	flag.IntVar(&meshnetHealMaxAttempts, "meshnet-heal-max-attempts", healDefaults.MaxAttempts,
		"Maximum number of times meshnet detect-and-heal recreates a single pod before giving up and emitting a Warning.")
	flag.DurationVar(&meshnetHealBackoff, "meshnet-heal-backoff", healDefaults.Backoff,
		"Minimum delay between successive meshnet detect-and-heal attempts on the same pod.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	cfg := ctrl.GetConfigOrDie()
	cfg.QPS = float32(kubeQPS)
	cfg.Burst = kubeBurst

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "a01e5ad3.dev.drivenets.net",
		// Release the leader lease promptly on shutdown so the new leader does
		// not have to wait LeaseDuration before starting. Safe because main()
		// exits as soon as Start returns.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.CdnosReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		APIReader:               mgr.GetAPIReader(),
		Recorder:                mgr.GetEventRecorderFor("cdnos-controller"),
		MaxConcurrentReconciles: maxConcurrentReconciles,
		MeshnetHeal: controller.MeshnetHealConfig{
			Enabled:     meshnetHealEnabled,
			GracePeriod: meshnetHealGrace,
			MaxAttempts: meshnetHealMaxAttempts,
			Backoff:     meshnetHealBackoff,
		},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Cdnos")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
