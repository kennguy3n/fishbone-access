// Command pam-gateway is the ShieldNet Access PAM multi-protocol proxy. It
// fronts privileged targets over SSH (2222), PostgreSQL (5432), MySQL (3306),
// and Kubernetes-exec (8443), recording sessions and appending to the PAM audit
// hash chain.
//
// Session 1A ships the boot/shutdown skeleton and the listener-address plan.
// The per-protocol ConnHandlers (wire-protocol proxying, CA-signed cert
// injection, IORecorder, command policy evaluation, audit chain) are
// implemented in Session 1D and registered on the gateway.Supervisor built
// here.
package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/kennguy3n/fishbone-access/internal/config"
	"github.com/kennguy3n/fishbone-access/internal/pkg/logger"
)

// protocolPlan documents the listener addresses pam-gateway will bind once the
// Session 1D handlers land. Kept here so deployment manifests (docker-compose,
// Helm) and this binary agree on ports.
var protocolPlan = []struct{ Name, Addr string }{
	{"ssh", ":2222"},
	{"postgres", ":5432"},
	{"mysql", ":3306"},
	{"k8s-exec", ":8443"},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()
	logger.Infof(ctx, "pam-gateway: starting; %s", cfg.String())
	for _, p := range protocolPlan {
		logger.Infof(ctx, "pam-gateway: protocol %q planned on %s (handler wired in Session 1D)", p.Name, p.Addr)
	}

	// Session 1D: build the protocol ConnHandlers and run the supervisor:
	//
	//	sup := gateway.NewSupervisor([]gateway.Listener{
	//		{Name: "ssh", Addr: ":2222", Handler: sshHandler},
	//		... postgres, mysql, k8s-exec ...
	//	})
	//	if err := sup.Run(ctx); err != nil { logger.Errorf(ctx, "%v", err) }
	logger.Infof(ctx, "pam-gateway: ready")
	<-ctx.Done()
	logger.Infof(context.Background(), "pam-gateway: shutting down")
}
