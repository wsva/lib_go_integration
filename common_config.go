package lib

import (
	"encoding/json"
	"os"
	"path"

	"github.com/tidwall/pretty"

	wl_db "github.com/wsva/lib_go_db"
)

const (
	CommonConfigFile = "common_config.json"
)

type CommonConfig struct {
	AccountAddress string   `json:"AccountAddress"`
	DB             wl_db.DB `json:"DB"`
}

func LoadCommonConfig(basepath, aesKey, aesIV string) (*CommonConfig, error) {
	contentBytes, err := os.ReadFile(
		path.Join(basepath, DirConfig, CommonConfigFile))
	if err != nil {
		return nil, err
	}
	var cc CommonConfig
	err = json.Unmarshal(contentBytes, &cc)
	if err != nil {
		return nil, err
	}
	err = EncryptCommonConfig(basepath, aesKey, aesIV, &cc)
	if err != nil {
		return nil, err
	}
	err = cc.DB.Decrypt(aesKey, aesIV)
	if err != nil {
		return nil, err
	}
	return &cc, nil
}

func EncryptCommonConfig(basepath, aesKey, aesIV string, cc *CommonConfig) error {
	mc := *cc
	err := mc.DB.Encrypt(aesKey, aesIV)
	if err != nil {
		return err
	}
	jsonBytes, err := json.Marshal(mc)
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(basepath, DirConfig, CommonConfigFile),
		pretty.Pretty(jsonBytes), 0666)
	if err != nil {
		return err
	}
	return nil
}
