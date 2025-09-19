package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luoying/gin-hander/pkg/rsautils"
	"github.com/pkg/errors"

	"github.com/luoying/gin-hander/pkg/log"
)

// 简单的设备验证
type DeviceToken struct {
	ID        string `header:"LY-Device-ID" binding:"required"`
	Timestamp int64  `header:"LY-Timestamp" binding:"required"`
	Signature string `header:"LY-Signature" binding:"required"`
}

// Validate 验证设备token
func (token *DeviceToken) Validate() error {
	if token.ID == "" {
		return StatusCodeDeviceRequired
	}

	if token.Signature == "" ||
		token.Timestamp == 0 {
		log.Warn("token missing arguments", "token", token)
		return StatusCodeBadToken
	}

	if time.Now().Unix()-token.Timestamp >= int64(time.Second*180) {
		log.Warn("token expired", "token", token)
		return StatusCodeTokenExpired
	}

	return nil
}

// packPayload 打包token payload
func (token *DeviceToken) packPayload() string {
	fields := []string{
		token.ID,
		strconv.FormatInt(token.Timestamp, 10),
	}
	sort.Strings(fields)
	return strings.Join(fields, "|")
}

func (token *DeviceToken) encryptPayload(pk *rsa.PublicKey) ([]byte, error) {
	signPayload := token.packPayload()
	encryptedData, err := rsautils.Encrypt(rsautils.ZeroReader(), pk, []byte(signPayload))
	if err != nil {
		return nil, errors.Wrap(err, "encryptPayload")
	}

	return encryptedData, nil
}

// ValidateWithKey 验证token是否有效
func (token *DeviceToken) ValidateWithKey(pk *rsa.PrivateKey) bool {
	encryptedData, err := token.encryptPayload(&pk.PublicKey)
	if err != nil {
		log.Warn("token encrypt payload failed", "token", token, "err", err)
		return false
	}

	hash := sha256.Sum256(encryptedData)
	hashOriEncryptData, err := base64.StdEncoding.DecodeString(token.Signature)
	if err != nil {
		log.Warn("token base64 decode Signature failed", "token", token, "err", err)
		return false
	}

	hashOri, err := rsautils.Decrypt(rand.Reader, pk, hashOriEncryptData)
	if err != nil {
		log.Warn("token decrypt Signature failed", "token", token, "err", err)
		return false
	}

	if !bytes.Equal(hashOri, hash[:]) {
		log.Warn("token not equal", "token", token)
		return false
	}

	return true
}

// GenerateSignature 生成token签名
func (token *DeviceToken) GenerateSignature(pk *rsa.PublicKey) error {
	encryptedData, err := token.encryptPayload(pk)
	if err != nil {
		return errors.Wrap(err, "encryptPayload")
	}

	hash := sha256.Sum256(encryptedData)
	hashEncryptedData, err := rsautils.Encrypt(rand.Reader, pk, hash[:])
	if err != nil {
		return errors.Wrap(err, "encryptHash")
	}

	token.Signature = base64.StdEncoding.EncodeToString(hashEncryptedData)
	return nil
}
