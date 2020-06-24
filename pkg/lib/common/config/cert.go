package config

type CertConfig struct {
	KeyFile      string `yaml:"key-file" mapstructure:"key-file"`
	CertFile     string `yaml:"cert-file" mapstructure:"cert-file"`
	CommonName   string `yaml:"common-name" mapstructure:"common-name"`
	SANList      string `yaml:"san-list" mapstructure:"san-list"`
	Issuer       string `yaml:"issuer" mapstructure:"issuer"`
	ValidityDays int    `yaml:"validity-days" mapstructure:"validity-days"`
}
