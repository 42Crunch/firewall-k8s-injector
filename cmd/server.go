package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/42crunch/kubernetes-injector/internal/server"
	"github.com/oklog/run"
	"github.com/sirupsen/logrus"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	"github.com/spf13/cobra"
)

type serverOption struct {
	server.ServerDefaults
	tlsCertFile string
	tlsKeyFile  string
}

func serverCmd() *cobra.Command {
	s := &serverOption{}
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start webhook server",
		Run:   s.run,
	}
	flags := cmd.Flags()
	flags.StringVarP(&s.tlsCertFile, "tls-cert-file", "c", "", "Certificate file name of TLS")
	flags.StringVarP(&s.tlsKeyFile, "tls-key-file", "k", "", "Key file name of TLS")
	flags.StringVarP(&s.ServerDefaults.Image, "image", "i", "42crunch/apifirewall:latest", "Firewall docker image")
	flags.StringVarP(&s.ServerDefaults.MaxMem, "max-memory", "m", "500Mi", "Firewall max memory")
	flags.StringVarP(&s.ServerDefaults.MaxCPU, "max-cpu", "u", "500m", "Firewall max CPU")
	flags.StringVarP(&s.ServerDefaults.Platform, "platform", "p", "protection.42crunch.com:8001", "Firewall platform")

	return cmd
}

func (o *serverOption) run(cmd *cobra.Command, args []string) {
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	if o.tlsCertFile == "" {
		logger.Errorf("tls-cert-file is required parameter")
	}

	if o.tlsKeyFile == "" {
		logger.Errorf("tls-key-file is required parameter")
	}

	var g run.Group

	sigC := make(chan os.Signal, 1)
	exitC := make(chan struct{})
	signal.Notify(sigC, syscall.SIGTERM, syscall.SIGINT)

	g.Add(
		func() error {
			select {
			case s := <-sigC:
				logger.Infof("signal %s received", s)
				return nil
			case <-exitC:
				return nil
			}
		},
		func(_ error) {
			close(exitC)
		},
	)

	server, err := server.CreateServer(&o.ServerDefaults)

	if err != nil {
		logger.Errorf("Could not create server: %s", err)
	}

	g.Add(
		func() error {
			logger.Infof("Webhook listening on port :8080")
			return server.ListenAndServeTLS(o.tlsCertFile, o.tlsKeyFile)

		},
		func(_ error) {
			logger.Infof("start draining connections")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := server.Shutdown(ctx)
			if err != nil {
				logger.Errorf("error while shutting down the server: %s", err)
			} else {
				logger.Infof("server stopped")
			}
		},
	)

	err = g.Run()
	if err != nil {
		logger.Errorf("error running server: %s", err)
	}

}
