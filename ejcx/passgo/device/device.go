package device

import (
	"github.com/Unknwon/goconfig"
	"os/exec"
	"os/user"
	"path/filepath"
	"log"
)

const (
	// ConfigFileName is the name of the passgo config file.
	ConfigFileName = "config"
	// SiteFileName is the name of the passgo password store file.
	SiteFileName = "sites.json"
	// AttackFileName is the name of the passgo under attack file.
	AttackFileName = "attacked"
	// EncryptedFileDir is the name of the passgo encrypted file dir.
	EncryptedFileDir = "files"
)

const (
	configFilename      = "config.txt"
	bootConfigFilename2 = "/boot/config2.txt"
	masterKeyMasked     = "--+*+--*++*--*+--+*+--*++*--*+--"
	pinCodeMasked       = "--*+--+**+--+*--*+--+**+--+**+--"
)

var (
	// MasterPassPrompt is the standard prompt string for all passgo
	MasterPassPrompt = "Enter master password"
	configPath       string
)

func init() {
	obtainHwCodes()

	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	homeDir := usr.HomeDir
	configPath = filepath.Join(homeDir, configFilename)
	if _, err := config(); err != nil {
		configPath = bootConfigFilename2
	}
	if absConfigPath, err := filepath.Abs(configPath); err == nil {
		configPath = absConfigPath
	} else {
		log.Printf("Error: file %s has some trouble getting to absolute format, giving %s\n", configPath, err)
	}
}

func Sudoer(command string) (result string, err error) {
	cmd := exec.Command("sudo", command)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error: %s\n", err)
	} else {
		result = string(stdoutStderr[:])
		log.Println(result)
	}
	return
}

func SudoPi(commands []string) (result string, err error) {
	//cmd, err := exec.Run("source")
	commands2 := []string{"source"}
	commands3 := append(commands2, commands[:]...)
	cmd := exec.Command("/bin/sh", commands3[:]...)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error: %s\n", err)
	} else {
		result = string(stdoutStderr[:])
		log.Println(result)
	}
	return
}

func ErasePinCode() {
	configFile, err := config()
	log.Printf("Error: device.ErasePinCode, configPath=%s\n", configPath)

	if err == nil {
		//log.Println("device.ErasePinCode, set value")
		configFile.SetValue("", "pincode", "----------**********----------//////////________")
		goconfig.SaveConfigFile(configFile, configPath)
	} else {
		log.Println("Error: device.ErasePinCode, value not set")
	}
}

func config() (*goconfig.ConfigFile, error) {
	configFile, err := goconfig.LoadConfigFile(configPath)
	if err != nil {
		//wd, _ := os.Getwd()
		//log.Printf("Error: config file %s could not be found, current dir=%s\n", configPath, wd)
	}
	return configFile, err
}

func AcceptKey(keyName string, keyFile string, keyMasked string) (key string, err error) {
	configFile, err := config()
	if err != nil {
		//wd, _ := os.Getwd()
		//log.Printf("Error: config file %s could not be found, current dir=%s\n", keyFile, wd)
	} else if key, err = configFile.GetValue("", keyName); err != nil {
		//wd, _ := os.Getwd()
		//log.Printf("Error: no %s in %s, current dir=%s\n\n", keyName, keyFile, wd)
		return
	} else if keyMasked != "" {
		configFile.SetValue("", keyName, keyMasked)
		goconfig.SaveConfigFile(configFile, keyFile)
	}
	return
}

func AcceptMasterKey() (masterKey string, err error) {
	return AcceptKey("masterkey", configPath, masterKeyMasked)
}

func AcceptPinCode() (pincode string, err error) {
	if mpinCode != "" {
		return mpinCode, nil
	} else {
		return AcceptKey("pincode", configPath, "")
	}
}

type Device interface {
	ObtainHwCode() (hwCode string, err error)
}

type SdCard struct {
	Device
}

type RpbPi struct {
	Device
}

func (SdCard) ObtainHwCode() (hwCode string, err error) {
	return obtainHwCode("cat /sys/block/mmcblk0/device/cid")
}
func (RpbPi) ObtainHwCode() (hwCode string, err error) {
	return obtainHwCode("cat /proc/cpuinfo|tail -3| cut -d':' -f 2")
}

func obtainHwCode(command string) (hwCode string, err error) {
	cmd := exec.Command("sh", "-c", command)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error trying to obtain hardware code: %s\n", err)
	} else {
		hwCode = string(stdoutStderr[:])
		//log.Println(hwCode)
	}
	return
}

var (
	hwCodeRpb string
	hwCodeSdc string
	err       error
	mpinCode  string
)

func obtainHwCodes() {
	/*if wd, error := os.Getwd(); error == nil {
		log.Printf("current path=%s\n", wd)
	}
	log.Println("device.obtainHwCodes was run")
	*/
	hwCodeRpb, err = RpbPi{}.ObtainHwCode()
	if err == nil {
		hwCodeSdc, err = SdCard{}.ObtainHwCode()
	}
	if err != nil {
		hwCodeRpb = ""
		hwCodeSdc = ""
	}
}

func GetHwCode() (hwcRpb string, hwcSdc string, err error) {
	hwcRpb, hwcSdc, err = hwCodeRpb, hwCodeSdc, err
	return
}

func Reprogram(pinCode string) {
	mpinCode = pinCode
}
