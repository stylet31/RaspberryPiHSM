// Package insert handles adding a new site to the password store.
package insert

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/sync"
	"golang.org/x/crypto/nacl/box"
	"io/ioutil"
	"log"
)

const (
	// PassPrompt is the string formatter that should be used
	// when prompting for a password.
	PassPrompt = "Enter password for %s"
)

// Password is used to add a new password entry to the vault.
func Password(name string) {
	sitePass, err := pio.PromptPass(fmt.Sprintf(PassPrompt, name), false)
	if err != nil {
		log.Fatalf("Could not get password for site: %s", err.Error())
	}
	GivenPassword(name, sitePass)
}

// GivenPassword is used to add a new password entry to the vault. The password is given as second argument.
func GivenPassword(name string, sitePass string) {

	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate site key: %s", err.Error())
	}

	config, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file name: %s", err.Error())
	}

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatalf("Could not get config file contents: %s", err.Error())
	}

	err = json.Unmarshal(configContents, &c)
	if err != nil {
		log.Fatalf("Could not unmarshal config file contents: %s", err.Error())
	}

	masterPub := c.MasterPubKey

	passSealed, err := pc.SealAsym([]byte(sitePass), &masterPub, priv)

	si := pio.SiteInfo{
		PubKey:     *pub,
		Name:       name,
		PassSealed: passSealed,
	}

	err = si.AddSite()
	if err != nil {
		log.Fatalf("Could not save site file: %s", err.Error())
	}
	sync.InsertCommit(name)
}

// File is used to add a new file entry to the vault.
func File(path, filename string) {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate site key: %s", err.Error())
	}

	config, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file name: %s", err.Error())
	}

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatalf("Could not get config file contents: %s", err.Error())
	}

	err = json.Unmarshal(configContents, &c)
	if err != nil {
		log.Fatalf("Could not unmarshal config file contents: %s", err.Error())
	}

	masterPub := c.MasterPubKey

	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Could not open and read file that is being encrypted: %s", err.Error())
	}

	fileSealed, err := pc.SealAsym([]byte(fileBytes), &masterPub, priv)
	if err != nil {
		log.Fatalf("Could not seal file bytes: %s", err.Error())
	}

	tokenFile, err := pc.GenHexString()
	if err != nil {
		log.Fatalf("Could not generate random string: %s", err.Error())
	}

	si := pio.SiteInfo{
		PubKey:   *pub,
		Name:     path,
		IsFile:   true,
		FileName: tokenFile,
	}

	err = si.AddFile(fileSealed, tokenFile)
	if err != nil {
		log.Fatalf("Could not save site file after file insert: %s", err.Error())
	}
	sync.InsertCommit(path)
}
