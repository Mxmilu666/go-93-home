package source

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ServerConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

type DatabaseConfig struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type SyncSourceConfig struct {
	NAME    string `yaml:name`
	URL     string `yaml:"url"`
	Branch  string `yaml:"branch"`
	DestDir string `yaml:"destDir"`
}

type Config struct {
	Server      ServerConfig       `yaml:"server"`
	Database    DatabaseConfig     `yaml:"database"`
	SyncSources []SyncSourceConfig `yaml:"syncSources"`
}

func CreateDefaultConfig(filename string) error {
	defaultConfig := Config{
		Server: ServerConfig{
			Address: "localhost",
			Port:    8080,
		},
		Database: DatabaseConfig{
			Address:  "localhost",
			Port:     27017,
			Username: "mongo",
			Password: "mongo",
		},
		SyncSources: []SyncSourceConfig{
			{
				NAME:    "test1",
				URL:     "https://github.com/example/repo1.git",
				Branch:  "main",
				DestDir: "repo1",
			},
			{
				NAME:    "test2",
				URL:     "https://github.com/example/repo2.git",
				Branch:  "dev",
				DestDir: "repo2",
			},
		},
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	defer encoder.Close()
	err = encoder.Encode(defaultConfig)
	if err != nil {
		return err
	}

	return nil
}

func ReadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
