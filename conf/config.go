package conf

import (
	"os"

	"github.com/luoying/gin-hander/pkg/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Config struct {
	Log        log.Option
	Listen     string
	Database   string
	UploadPath string
	ExportPath string
	db         *gorm.DB
}

// DB 返回数据库连接
func (c *Config) DB() *gorm.DB {
	return c.db
}

// defaultConfig 返回默认配置
func defaultConfig() *Config {
	return &Config{
		Listen:     ":8080",
		Database:   defaultDatabase,
		UploadPath: defaultUploadDir,
		ExportPath: defaultExportDir,
	}
}

func initDatabase(config *Config) (*Config, error) {
	var err error
	if config.Database == emptyString {
		config.Database = defaultDatabase
	}
	config.db, err = gorm.Open(sqlite.Open(config.Database), &gorm.Config{})
	return config, err
}

// LoadAppConfig 加载应用配置

func LoadAppConfig() (*Config, error) {
	return LoadConfig(configFilename, func() (*Config, error) {
		return defaultConfig(), nil
	},
		func(config *Config) (*Config, error) {
			return WriteDefaultConfig(configFilename, config)
		},
		func(config *Config) (*Config, error) {
			log.Apply(&config.Log)
			return config, nil
		},
		initDatabase,
		initPath,
		func(config *Config) (*Config, error) {
			return WriteDefaultConfig(configFilename, config)
		},
	)
}

func createDirIfNotExists(path string) error {
	err := os.MkdirAll(path, 0755) // 显式设置权限为 0755
	if err != nil {
		return err
	}
	return nil
}

// InitPath 初始化上传和导出目录
func initPath(config *Config) (*Config, error) {
	err := createDirIfNotExists(config.UploadPath)
	if err != nil {
		return nil, err
	}
	err = createDirIfNotExists(config.ExportPath)
	if err != nil {
		return nil, err
	}
	return config, nil
}
