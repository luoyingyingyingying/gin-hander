package conf

import (
	"errors"
	"os"

	"github.com/luoying/gin-hander/pkg/log"
	"github.com/luoying/gin-hander/pkg/utils"
	"github.com/pelletier/go-toml/v2"
)

// LoadConfigFile 加载配置文件
func LoadConfigFile[T any](filename string, cfg T) (T, error) {
	if _, err := os.Stat(filename); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if buf, err := os.ReadFile(filename); err != nil {
		return cfg, err
	} else {
		return cfg, toml.Unmarshal(buf, cfg)
	}
}

// WriteDefaultConfig 写入默认配置文件
func WriteDefaultConfig[T any](filename string, cfg T) (T, error) {
	if _, err := os.Stat(filename); err == nil || !os.IsNotExist(err) {
		return cfg, err
	}
	f, err := os.Create(filename)
	if err != nil {
		return cfg, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warn("write default config error", err)
		}
	}()
	return cfg, toml.NewEncoder(f).Encode(cfg)
}

// LoadConfig 加载配置
func LoadConfig[T any](filename string, defaultConfig func() (T, error), opt ...func(T) (T, error)) (T, error) {
	cfg, err := defaultConfig()
	if err != nil {
		log.Warn("load default config failed", err)
		return cfg, err
	}

	opt = append([]func(T) (T, error){
		func(t T) (T, error) {
			return LoadConfigFile(filename, t)
		},
	}, opt...)
	return utils.Apply(cfg, opt...)
}
