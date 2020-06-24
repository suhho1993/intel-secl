package hvs

import (
	"crypto/x509/pkix"
	"fmt"
	"path"
	"strings"

	"github.com/intel-secl/intel-secl/v3/pkg/hvs/config"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/constants"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/tasks"
	commConfig "github.com/intel-secl/intel-secl/v3/pkg/lib/common/config"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault("tls-cert-file", constants.DefaultTLSCertFile)
	viper.SetDefault("tls-key-file", constants.DefaultTLSKeyFile)
	viper.SetDefault("tls-common-name", constants.DefaultHvsTlsCn)
	viper.SetDefault("tls-san-list", constants.DefaultHvsTlsSan)
	viper.SetDefault("tls-issuer", constants.NAString)
	viper.SetDefault("tls-validity-days", 0)

	// set default values for all other certs
	viper.SetDefault("saml-cert-file", constants.SAMLCertFile)
	viper.SetDefault("saml-key-file", constants.SAMLKeyFile)
	viper.SetDefault("saml-common-name", constants.DefaultCN)
	viper.SetDefault("saml-san-list", constants.DefaultSANList)
	viper.SetDefault("saml-issuer", constants.NAString)
	viper.SetDefault("saml-validity-days", 0)

	viper.SetDefault("flavor-signing-cert-file", constants.FlavorSigningCertFile)
	viper.SetDefault("flavor-signing-key-file", constants.FlavorSigningKeyFile)
	viper.SetDefault("flavor-signing-common-name", constants.DefaultCN)
	viper.SetDefault("flavor-signing-san-list", constants.DefaultSANList)
	viper.SetDefault("flavor-signing-issuer", constants.NAString)
	viper.SetDefault("flavor-signing-validity-days", 0)

	viper.SetDefault("privacy-ca-cert-file", constants.PrivacyCACertFile)
	viper.SetDefault("privacy-ca-key-file", constants.PrivacyCAKeyFile)
	viper.SetDefault("privacy-ca-common-name", constants.DefaultCN)
	viper.SetDefault("privacy-ca-san-list", constants.DefaultSANList)
	viper.SetDefault("privacy-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("privacy-ca-validity-days", constants.DefaultCertValidity)

	viper.SetDefault("endorsement-ca-cert-file", constants.EndorsementCACertFile)
	viper.SetDefault("endorsement-ca-key-file", constants.EndorsementCAKeyFile)
	viper.SetDefault("endorsement-ca-common-name", constants.DefaultCN)
	viper.SetDefault("endorsement-ca-san-list", constants.DefaultSANList)
	viper.SetDefault("endorsement-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("endorsement-ca-validity-days", constants.DefaultCertValidity)

	viper.SetDefault("tag-ca-cert-file", constants.TagCACertFile)
	viper.SetDefault("tag-ca-key-file", constants.TagCAKeyFile)
	viper.SetDefault("tag-ca-common-name", constants.DefaultCN)
	viper.SetDefault("tag-ca-san-list", constants.DefaultSANList)
	viper.SetDefault("tag-ca-issuer", constants.DefaultCertIssuer)
	viper.SetDefault("tag-ca-validity-days", constants.DefaultCertValidity)

	// set default values for log
	viper.SetDefault("log-max-length", constants.DefaultLogEntryMaxlength)
	viper.SetDefault("log-enable-stdout", true)
	viper.SetDefault("log-level", "error")

	// set default values for privacy ca
	viper.SetDefault("privacy-ca-cert-validity", constants.DefaultPrivacyCACertValidity)
	viper.SetDefault("privacy-ca-id-issuer", constants.DefaultPrivacyCaIdentityIssuer)

	// set default values for server
	viper.SetDefault("server-port", constants.DefaultHVSListenerPort)
	viper.SetDefault("server-read-timeout", constants.DefaultReadTimeout)
	viper.SetDefault("server-read-header-timeout", constants.DefaultReadHeaderTimeout)
	viper.SetDefault("server-write-timeout", constants.DefaultWriteTimeout)
	viper.SetDefault("server-idle-timeout", constants.DefaultIdleTimeout)
	viper.SetDefault("server-max-header-bytes", constants.DefaultMaxHeaderBytes)

	// set default for database ssl certificate
	viper.SetDefault("database-ssl-cert", constants.ConfigDir+"hvsdbsslcert.pem")
}

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
				break
			} else {
				return errors.New("Invalid answer file name")
			}
		}
		if s == "--force" {
			force = true
		}
	}
	// Load configuration
	// use default config if failed
	var err error
	defaultConfigLoaded := false
	a.Config, err = config.LoadConfiguration()
	if err != nil {
		// if the default config is loaded,
		// it should force to take in env variables if there is any
		defaultConfigLoaded = true
		a.Config = defaultConfig()
	}
	defer a.Config.Save(path.Join(a.configDir(), "config.yaml"))

	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			fmt.Fprintln(a.errorWriter(), "Failed to run all setup task")
			fmt.Fprintln(a.errorWriter(), "Please make sure following requirements are met")
			runner.PrintAllHelp()
			return errors.Wrap(err, "Failed to run all tasks")
		}
	} else {
		force = defaultConfigLoaded
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), "Failed to run setup task", cmd)
			fmt.Fprintln(a.errorWriter(), "Please make sure following requirements are met")
			runner.PrintHelp(cmd)
			return errors.Wrap(err, "Failed to run setup task: "+cmd)
		}
	}
	return nil
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*setup.Runner, error) {

	// viper.SetEnvPrefix("APP")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask("server", "", &tasks.ServerSetup{
		SvrConfigPtr: &a.Config.Server,
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("database", "", &tasks.DBSetup{
		DBConfigPtr: &a.Config.DB,
		DBConfig: commConfig.DBConfig{
			Vendor:   viper.GetString("database-vendor"),
			Host:     viper.GetString("database-host"),
			Port:     viper.GetString("database-port"),
			DBName:   viper.GetString("database-db-name"),
			Username: viper.GetString("database-username"),
			Password: viper.GetString("database-password"),
			SSLMode:  viper.GetString("database-ssl-mode"),
			SSLCert:  viper.GetString("database-ssl-cert"),

			ConnectionRetryAttempts: viper.GetInt("database-conn-retry-attempts"),
			ConnectionRetryTime:     viper.GetInt("database-conn-retry-time"),
		},
		SSLCertSource: viper.GetString("database-ssl-cert-source"),
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedRootCACertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		TlsCertDigest: viper.GetString("cms-tls-cert-sha384"),
	})
	runner.AddTask("download-cert-tls", "tls", a.downloadCertTask("tls"))
	runner.AddTask("download-cert-saml", "saml", a.downloadCertTask("saml"))
	runner.AddTask("download-cert-flavor-signing", "flavor-signing", a.downloadCertTask("flavor-signing"))

	runner.AddTask("create-privacy-ca", "privacy-ca", a.selfSignTask("privacy-ca"))
	runner.AddTask("create-endorsement-ca", "endorsement-ca", a.selfSignTask("endorsement-ca"))
	runner.AddTask("create-tag-ca", "tag-ca", a.selfSignTask("tag-ca"))

	return runner, nil
}

func (a *App) downloadCertTask(certType string) setup.Task {
	var updateConfig *commConfig.CertConfig
	certTypeReq := certType
	switch certType {
	case "tls":
		updateConfig = &a.configuration().TLS
	case "saml":
		updateConfig = &a.configuration().SAML
		certTypeReq = "signing"
	case "flavor-signing":
		updateConfig = &a.configuration().FlavorSigning
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(certType + "-key-file")
		updateConfig.CertFile = viper.GetString(certType + "-cert-file")
		updateConfig.CommonName = viper.GetString(certType + "-common-name")
		updateConfig.SANList = viper.GetString(certType + "-san-list")
	}
	return &setup.DownloadCert{
		KeyFile:            viper.GetString(certType + "-key-file"),
		CertFile:           viper.GetString(certType + "-cert-file"),
		KeyAlgorithm:       constants.DefaultKeyAlgorithm,
		KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(certType + "-common-name"),
		},
		SanList:       viper.GetString(certType + "-san-list"),
		CertType:      certTypeReq,
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString("cms-base-url"),
		BearerToken:   viper.GetString("bearer-token"),
	}
}

func (a *App) selfSignTask(name string) setup.Task {
	var updateConfig *commConfig.CertConfig
	switch name {
	case "privacy-ca":
		updateConfig = &a.configuration().PrivacyCA
	case "endorsement-ca":
		updateConfig = &a.configuration().EndorsementCA
	case "tag-ca":
		updateConfig = &a.configuration().TagCA
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(name + "-key-file")
		updateConfig.CertFile = viper.GetString(name + "-cert-file")
		updateConfig.CommonName = viper.GetString(name + "-common-name")
		updateConfig.SANList = viper.GetString(name + "-san-list")
		updateConfig.Issuer = viper.GetString(name + "-issuer")
		updateConfig.ValidityDays = viper.GetInt(name + "-validity-days")
	}
	return &setup.SelfSignedCert{
		CertFile:     viper.GetString(name + "-cert-file"),
		KeyFile:      viper.GetString(name + "-key-file"),
		CommonName:   viper.GetString(name + "-common-name"),
		Issuer:       viper.GetString(name + "-issuer"),
		SANList:      viper.GetString(name + "-san-list"),
		ValidityDays: viper.GetInt(name + "-validity-days"),

		ConsoleWriter: a.consoleWriter(),
	}
}

func defaultConfig() *config.Configuration {
	return &config.Configuration{
		TLS: commConfig.CertConfig{
			CertFile:     viper.GetString("tls-cert-file"),
			KeyFile:      viper.GetString("tls-key-file"),
			CommonName:   viper.GetString("tls-common-name"),
			SANList:      viper.GetString("tls-san-list"),
			Issuer:       viper.GetString("tls-issuer"),
			ValidityDays: viper.GetInt("tls-validity-days"),
		},
		SAML: commConfig.CertConfig{
			CertFile:     viper.GetString("saml-cert-file"),
			KeyFile:      viper.GetString("saml-key-file"),
			CommonName:   viper.GetString("saml-common-name"),
			SANList:      viper.GetString("saml-san-list"),
			Issuer:       viper.GetString("saml-issuer"),
			ValidityDays: viper.GetInt("saml-validity-days"),
		},
		FlavorSigning: commConfig.CertConfig{
			CertFile:     viper.GetString("flavor-signing-cert-file"),
			KeyFile:      viper.GetString("flavor-signing-key-file"),
			CommonName:   viper.GetString("flavor-signing-common-name"),
			SANList:      viper.GetString("flavor-signing-san-list"),
			Issuer:       viper.GetString("flavor-signing-issuer"),
			ValidityDays: viper.GetInt("flavor-signing-validity-days"),
		},
		PrivacyCA: commConfig.CertConfig{
			CertFile:     viper.GetString("privacy-ca-cert-file"),
			KeyFile:      viper.GetString("privacy-ca-key-file"),
			CommonName:   viper.GetString("privacy-ca-common-name"),
			SANList:      viper.GetString("privacy-ca-san-list"),
			Issuer:       viper.GetString("privacy-ca-issuer"),
			ValidityDays: viper.GetInt("privacy-ca-validity-days"),
		},
		EndorsementCA: commConfig.CertConfig{
			CertFile:     viper.GetString("endorsement-ca-cert-file"),
			KeyFile:      viper.GetString("endorsement-ca-key-file"),
			CommonName:   viper.GetString("endorsement-ca-common-name"),
			SANList:      viper.GetString("endorsement-ca-san-list"),
			Issuer:       viper.GetString("endorsement-ca-issuer"),
			ValidityDays: viper.GetInt("endorsement-ca-validity-days"),
		},
		TagCA: commConfig.CertConfig{
			CertFile:     viper.GetString("tag-ca-cert-file"),
			KeyFile:      viper.GetString("tag-ca-key-file"),
			CommonName:   viper.GetString("tag-ca-common-name"),
			SANList:      viper.GetString("tag-ca-san-list"),
			Issuer:       viper.GetString("tag-ca-issuer"),
			ValidityDays: viper.GetInt("tag-ca-validity-days"),
		},
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt("log-max-length"),
			EnableStdout: viper.GetBool("log-enable-stdout"),
			Level:        viper.GetString("log-level"),
		},
		Server: commConfig.ServerConfig{
			Port:              viper.GetInt("server-port"),
			ReadTimeout:       viper.GetDuration("server-read-timeout"),
			ReadHeaderTimeout: viper.GetDuration("server-read-header-timeout"),
			WriteTimeout:      viper.GetDuration("server-write-timeout"),
			IdleTimeout:       viper.GetDuration("server-idle-timeout"),
			MaxHeaderBytes:    viper.GetInt("server-max-header-bytes"),
		},
	}
}
