package config

type LogConfig struct {
	MaxLength    int    `yaml:"max-length" mapstructure:"max-length"`
	EnableStdout bool   `yaml:"enable-stdout" mapstructure:"enable-stdout"`
	Level        string `yaml:"level" mapstructure:"level"`
}
