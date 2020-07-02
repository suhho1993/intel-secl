package hvs

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/postgres"
	hostfetcher "github.com/intel-secl/intel-secl/v3/pkg/hvs/services/host-fetcher"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/services/hosttrust"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/crypt"
	hostconnector "github.com/intel-secl/intel-secl/v3/pkg/lib/host-connector"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/saml"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/verifier"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/router"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/utils"

	stdlog "log"

	commLog "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log"
	commLogMsg "github.com/intel-secl/intel-secl/v3/pkg/lib/common/log/message"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func (a *App) startServer() error {
	defaultLog.Trace("app:startServer() Entering")
	defer defaultLog.Trace("app:startServer() Leaving")

	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration")
	}
	// initialize log
	if err := a.configureLogs(c.Log.EnableStdout, true); err != nil {
		return err
	}

	// Initialize Database
	dataStore := postgres.InitDatabase(c)

	// Load Certificates
	certStore := utils.LoadCertificates(a.loadCertPathStore())

	// Initialize Host trust manager
	hostTrustManager := initHostTrustManager(c, dataStore, certStore)

	// Initialize routes
	routes := router.InitRoutes(c, dataStore, certStore, hostTrustManager)

	defaultLog.Info("Starting server")
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Server.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), routes)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsConfig,
		ReadTimeout:       c.Server.ReadTimeout,
		ReadHeaderTimeout: c.Server.ReadHeaderTimeout,
		WriteTimeout:      c.Server.WriteTimeout,
		IdleTimeout:       c.Server.IdleTimeout,
		MaxHeaderBytes:    c.Server.MaxHeaderBytes,
	}

	tlsCert := c.TLS.CertFile
	tlsKey := c.TLS.KeyFile
	// dispatch web server go routine
	go func() {
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			defaultLog.WithError(err).Info("Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	secLog.Info(commLogMsg.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		defaultLog.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	secLog.Info(commLogMsg.ServiceStop)
	return nil
}

func initHostTrustManager(cfg *config.Configuration, dataStore *postgres.DataStore, certStore *models.CertificatesStore) domain.HostTrustManager {
	defaultLog.Trace("server:InitHostTrustManager() Entering")
	defer defaultLog.Trace("server:InitHostTrustManager() Leaving")

	//Load store
	hs := postgres.NewHostStore(dataStore)
	fs := postgres.NewFlavorStore(dataStore)
	fgs := postgres.NewFlavorGroupStore(dataStore)
	qs := postgres.NewDBQueueStore(dataStore)
	hss := postgres.NewHostStatusStore(dataStore)
	rs := postgres.NewReportStore(dataStore)

	//Load certificates
	rootCAs := (*certStore)[models.CaCertTypesRootCa.String()]
	tagCAs := (*certStore)[models.CaCertTypesTagCa.String()]
	privacyCAs := (*certStore)[models.CaCertTypesPrivacyCa.String()]
	//TODO: Add flavor signing certificate
	verifierCerts := verifier.VerifierCertificates{
		PrivacyCACertificates:    crypt.GetCertPool(privacyCAs.Certificates),
		AssetTagCACertificates:   crypt.GetCertPool(tagCAs.Certificates),
		FlavorSigningCertificate: nil,
		FlavorCACertificates:     crypt.GetCertPool(rootCAs.Certificates),
	}
	libVerifier, _ := verifier.NewVerifier(verifierCerts)

	tagKey := (*tagCAs.Key).(rsa.PrivateKey)
	tagIssuerConfig := saml.IssuerConfiguration{
		IssuerName:        cfg.TagCA.Issuer,
		IssuerServiceName: constants.ServiceName,
		ValiditySeconds:   cfg.TagCA.ValidityDays * 86400, //Day to seconds
		PrivateKey:        &tagKey,
		Certificate:       &tagCAs.Certificates[0],
	}

	htv := domain.HostTrustVerifierConfig{
		FlavorStore:      fs,
		FlavorGroupStore: fgs,
		HostStore:        hs,
		ReportStore:      rs,
		FlavorVerifier:   libVerifier,
		CertsStore:       *certStore,
		TagIssuerConfig:  tagIssuerConfig,
	}

	// Initialize Host Fetcher service
	// TODO: Read Workers from config

	htcFactory := hostconnector.NewHostConnectorFactory(cfg.AASApiUrl, rootCAs.Certificates)

	c := domain.HostDataFetcherConfig{HostConnectorFactory: *htcFactory}
	_, hf, _ := hostfetcher.NewService(c, 5)

	// Initialize Host Trust service
	// TODO: Read Verifiers from config
	_, htm, _ := hosttrust.NewService(domain.HostTrustMgrConfig{
		PersistStore: qs,
		HostStore:    hs,
		HostStatusStore: hss,
		HostFetcher:  hf,
		Verifiers:    5,
		HostTrustVerifier: hosttrust.NewVerifier(htv),
	})

	return htm
}

func (a *App) loadCertPathStore() *models.CertificatesPathStore {
	// constants are used somewhere else in the repo
	// change it into the configured paths after fixing all of them
	// currently used constants:
	//     TrustedRootCACertsDir, PrivacyCAKeyFile, PrivacyCACertFile
	return &models.CertificatesPathStore{
		models.CaCertTypesRootCa.String(): models.CertLocation{
			KeyFile:  "",
			CertPath: constants.TrustedRootCACertsDir,
		},
		models.CaCertTypesEndorsementCa.String(): models.CertLocation{
			KeyFile:  constants.EndorsementCAKeyFile,
			CertPath: constants.EndorsementCACertDir,
		},
		models.CaCertTypesPrivacyCa.String(): models.CertLocation{
			KeyFile:  constants.PrivacyCAKeyFile,
			CertPath: constants.PrivacyCACertFile,
		},
		models.CaCertTypesTagCa.String(): models.CertLocation{
			KeyFile:  constants.TagCAKeyFile,
			CertPath: constants.TagCACertFile,
		},
		models.CertTypesSaml.String(): models.CertLocation{
			KeyFile:  constants.SAMLKeyFile,
			CertPath: constants.SAMLCertFile,
		},
		models.CertTypesTls.String(): models.CertLocation{
			KeyFile:  constants.DefaultTLSKeyFile,
			CertPath: constants.DefaultTLSCertFile,
		},
	}
}
