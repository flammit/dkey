package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

const (
	seedSize = 32
)

type randReader struct {
	seed, salt, key []byte
	mu              *sync.RWMutex
	total           int
}

func (r *randReader) Read(p []byte) (int, error) {
	// https://github.com/cornfeedhobo/ssh-keydgen/blob/master/slowseeder/slowseeder.go
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seed = pbkdf2.Key(r.seed, r.key, 16, sha512.Size, sha512.New)
	r.salt = pbkdf2.Key(r.salt, r.key, 16, ripemd160.Size, ripemd160.New)
	r.key = argon2.Key(r.seed, r.salt, 1, 64*1024, 4, uint32(len(p)))
	r.total += len(p)
	return copy(p, r.key), nil
}

type key []byte

func (k key) extendKey(name string) key {
	// HMAC-SHA256
	h := hmac.New(sha256.New, k)
	h.Write([]byte(name))
	return h.Sum(nil)
}

func (k key) generateKey(basePath, path string) key {
	pathList := strings.Split(path, "/")
	if len(pathList) > 1 {
		newBasePath := filepath.Join(basePath, pathList[0])
		newPath := filepath.Join(pathList[1:]...)

		// check for existence of override key
		newDirKey, err := loadKey(newBasePath)
		if err != nil {
			newDirKey = k.extendKey(pathList[0])
		}
		return newDirKey.generateKey(newBasePath, newPath)
	}
	fileKey := k.extendKey(pathList[0])
	return fileKey
}

func (k key) newRandReader() *randReader {
	return &randReader{
		seed: k,
		salt: k,
		mu:   &sync.RWMutex{},
	}
}

func (k key) generateRsaKey() (*rsa.PrivateKey, error) {
	bitSize := 2048
	privateKey, err := rsa.GenerateKey(k.newRandReader(), bitSize)
	if err != nil {
		return nil, err
	}
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func loadKey(dir string) (key, error) {
	// check for raw ".dkey_master" file
	master, err := ioutil.ReadFile(filepath.Join(dir, ".dkey_master"))
	if err == nil {
		if len(master) != seedSize {
			return nil, fmt.Errorf("invalid master key length: expected=%v got=%v",
				seedSize, len(master))
		}
		return key(master), nil
	}

	// check for user password ".rekey_pass" file
	pass, err := ioutil.ReadFile(filepath.Join(dir, ".dkey_pass"))
	if err == nil {
		salt := pbkdf2.Key(pass, pass, 1024, sha512.Size, sha512.New)
		key := argon2.IDKey(pass, salt, 256, 64*1024, 4, seedSize)
		return key, nil
	}
	return nil, fmt.Errorf("missing .dkey_pass or .dkey_master in dir '%v'", dir)
}

type keyConfig struct {
	path    string
	key     key
	options map[string]string
}

func (c keyConfig) KeyPath(file string) string {
	return filepath.Join(c.path, file)
}

const (
	readOnlyMode = 0600
)

type appKey interface {
	OutputKeys(config *keyConfig) error
}

type defaultKey struct{}

func (k defaultKey) OutputKeys(config *keyConfig) error {
	// write the secret to .dkey_master
	keyPath := config.KeyPath(".dkey_master")
	err := ioutil.WriteFile(keyPath, config.key, readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write key file '%v': err=%v", keyPath, err)
	}
	return nil
}

type wireguardKey struct{}

func (k wireguardKey) OutputKeys(config *keyConfig) error {
	// clamp the curve25519 key -- see https://git.zx2c4.com/WireGuard/tree/src/tools/curve25519.h
	config.key[0] &= 248
	config.key[31] = (config.key[31] & 127) | 64

	// write the private key to "private_key"
	privKeyData := []byte(base64.StdEncoding.EncodeToString(config.key))
	privKeyPath := config.KeyPath("private_key")
	err := ioutil.WriteFile(privKeyPath, privKeyData, readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write wireguard private key file '%v': err=%v", privKeyPath, err)
	}
	return nil
}

type sshRSAKey struct{}

func (k sshRSAKey) OutputKeys(config *keyConfig) error {
	privateKey, err := config.key.generateRsaKey()
	if err != nil {
		return fmt.Errorf("failed to generate RSA key for ssh key: err=%v", err)
	}

	// write private key
	privKeyPath := config.KeyPath("id_rsa")
	privKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = ioutil.WriteFile(privKeyPath, privKeyBytes, readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write ssh rsa private key '%v': err=%v", privKeyPath, err)
	}

	// write public key
	pubKeyPath := config.KeyPath("id_rsa.pub")
	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to generate ssh public key: err=%v", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	err = ioutil.WriteFile(pubKeyPath, pubKeyBytes, readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write ssh rsa public key '%v': err=%v", pubKeyPath, err)
	}
	// log.Printf("ssh rsa key '%v': pub=%v", config.path, string(pubKeyBytes))

	return nil
}

// TODO: https://github.com/mikesmitty/edkey
// no dropbear support for ed25519 keys
// https://github.com/pts/pts-dropbear / https://github.com/mkj/dropbear/pull/75
/*
type sshED25519Key struct{}

func (k sshED25519Key) OutputKeys(config *keyConfig) error {
	return nil
}
*/

type gpgRSAKey struct{}

func (k gpgRSAKey) OutputKeys(config *keyConfig) error {
	pktConfig := &packet.Config{
		Rand:    config.key.newRandReader(),
		RSABits: 2048,
	}
	entity, err := openpgp.NewEntity(
		config.options["name"],
		config.options["comment"],
		config.options["email"],
		pktConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to generate entity for gpg key: err=%v", err)
	}

	privBuf := bytes.NewBuffer([]byte{})
	privCloser, err := armor.Encode(privBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armored private key encoder: err=%v", err)
	}
	err = entity.SerializePrivate(privCloser, pktConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize gnupg private key: err=%v", err)
	}
	privCloser.Close()
	privKeyPath := config.KeyPath("private.asc")
	err = ioutil.WriteFile(privKeyPath, privBuf.Bytes(), readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write gnupg private key '%v': err=%v", privKeyPath, err)
	}

	pubBuf := bytes.NewBuffer([]byte{})
	pubCloser, err := armor.Encode(pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to create armored public key encoder: err=%v", err)
	}
	err = entity.Serialize(pubCloser)
	if err != nil {
		return fmt.Errorf("failed to serialize gnupg public key: err=%v", err)
	}
	pubCloser.Close()
	pubKeyPath := config.KeyPath("public.asc")
	err = ioutil.WriteFile(pubKeyPath, pubBuf.Bytes(), readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write gnupg public key '%v': err=%v", pubKeyPath, err)
	}
	// log.Printf("gpg key '%v': pub=%v", config.path, pubBuf.String())
	return nil
}

// TODO:
// golang openpgp doesn't have support for this yet...
// https://github.com/ProtonMail/crypto has support
// https://github.com/keybase/go-crypto has support
/*
type gpgED25519Key struct{}

func (k gpgED25519Key) OutputKeys(config *keyConfig) error {
	return nil
}
*/

type luksKey struct{}

func (k luksKey) OutputKeys(config *keyConfig) error {
	randReader := config.key.newRandReader()
	size := 4096 / 8 // TODO: read size from config
	keyBytes := make([]byte, size)
	randReader.Read(keyBytes)
	keyPath := config.KeyPath("keyfile")
	err := ioutil.WriteFile(keyPath, keyBytes, readOnlyMode)
	if err != nil {
		return fmt.Errorf("failed to write luks keyfile '%v': err=%v", keyPath, err)
	}
	return nil
}

var (
	appTypes = map[string]appKey{
		"master":    defaultKey{},
		"aes-256":   defaultKey{},
		"wireguard": wireguardKey{},
		"ssh-rsa":   sshRSAKey{},
		// "ssh-ed25519": sshED25519Key{},
		"gpg-rsa": gpgRSAKey{},
		// "gpg-ed25519": gpgED25519Key{},
		"luks": luksKey{},
	}
)

func parseOptions(sOptions string) map[string]string {
	pairs := strings.Split(sOptions, ",")
	if len(pairs) == 0 {
		return nil
	}
	m := map[string]string{}
	for _, pair := range pairs {
		fields := strings.Split(pair, "=")
		if len(fields) > 2 || len(fields) == 0 {
			continue
		}
		key := fields[0]
		val := ""
		if len(fields) > 1 {
			val = fields[1]
		}
		m[key] = val
	}
	return m
}

type appConfig struct {
	Path    string
	App     string
	Options map[string]string
}

func (config appConfig) Process(rootKey key, baseDir string) {
	path := filepath.Join(baseDir, config.Path)
	key := rootKey.generateKey(baseDir, config.Path)
	log.Printf("file key '%v' type '%v'", config.Path, config.App)
	// log.Printf("file key '%v' type '%v': %v", config.Path, config.App,
	// 	base64.StdEncoding.EncodeToString(key))

	appType, ok := appTypes[config.App]
	if !ok {
		log.Fatalf("invalid app type '%v'", config.App)
	}
	err := os.MkdirAll(path, 0700)
	if err != nil {
		log.Fatalf("failed to create directory to '%v': err=%v", path, err)
	}
	keyConfig := &keyConfig{
		path:    path,
		key:     key,
		options: config.Options,
	}
	err = appType.OutputKeys(keyConfig)
	if err != nil {
		log.Fatalf("failed to output keys for '%v' type '%v': err=%v",
			config.Path, config.App, err)
	}
}

func parseConfig(config string) *appConfig {
	var path, app string
	appOptions := map[string]string{}
	parts := strings.Split(config, ":")
	if len(parts) == 0 || len(parts[0]) == 0 {
		return nil
	}
	path = parts[0]
	if len(parts) > 1 {
		app = parts[1]
	}
	if len(parts) > 2 {
		appOptions = parseOptions(parts[2])
	}
	return &appConfig{
		Path:    path,
		App:     app,
		Options: appOptions,
	}
}

func loadConfig(baseDir string) ([]*appConfig, error) {
	// read lines
	configPath := filepath.Join(baseDir, ".dkey_config")
	bytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at '%v': err=%v",
			configPath, err)
	}
	lines := strings.Split(string(bytes), "\n")
	configs := []*appConfig{}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		config := parseConfig(line)
		if config != nil {
			configs = append(configs, config)
		}
	}
	return configs, err
}

func main() {
	baseDir := "."
	if len(os.Args) > 1 {
		baseDir = os.Args[1]
	}

	now := time.Now()
	rootKey, err := loadKey(baseDir)
	if err != nil {
		log.Fatalf("main.loadKey: err=%v", err)
	}
	log.Printf("root key: load took %v ms", ((time.Now().UnixNano() - now.UnixNano()) / 1000000))
	// log.Printf("root key: %v", base64.StdEncoding.EncodeToString(rootKey))

	configs, err := loadConfig(baseDir)
	if err != nil {
		log.Fatalf("main.loadConfig: err=%v", err)
	}
	for _, config := range configs {
		config.Process(rootKey, baseDir)
	}
}
