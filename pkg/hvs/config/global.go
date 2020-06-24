package config

// this function is for compatibility with older code
// we should stop using it and switch to having configuration
// read from application structure

var globalConfig *Configuration

func Global() *Configuration {
	if globalConfig == nil {
		globalConfig, _ = LoadConfiguration()
	}
	return globalConfig
}
