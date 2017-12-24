package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ejcx/passgo/device"
	"github.com/ejcx/passgo/edit"
	"github.com/ejcx/passgo/generate"
	"github.com/ejcx/passgo/initialize"
	"github.com/ejcx/passgo/insert"
	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/show"
	"github.com/ejcx/passgo/sync"

	"log"
)

const (
	ALLARGS = -1
)

var (
	// copyPass indicates that the shown password should be copied to the clipboard.
	copyPass = flag.Bool("copy", false, "If true, copy password to clipboard instead of displaying it")
	// userName indicates that the home directory is taken from someone else instead of the current user
	userName = flag.String("user", "pi", "If set, chooses the user of the home directory instead of the current user")
	// pincode indicates which pincode will open the vault
	pincode = flag.String("pincode", "", "if set it will be used to open the vault")

	version = `======================================
= passgo: v1.0                       =
= The simple golang password and     =
= file manager                       =
=                                    =
= Twiinsen Security                  =
= evan@twiinsen.com                  =
= https://twiinsen.com/passgo        =
======================================`
	usage = `Usage:
	passgo
		Print the contents of the vault.
	passgo show site-path
		Print the password of a passgo entry.
	passgo init
		Initialize the .passgo directory, and generate your secret keys.
	passgo initfromhardware
		Take a master key from existing hardware, including a preloaded pincode.txt special code
		which will be purposely	erased once loaded.
	passgo acceptpincode
		Replace all master key requests with a preloaded pincode.txt special code, erased once loaded as before.
	passgo insert site-path
		Add a site to your password store. This site can optionally be a part
		of a group by prepending a group name and slash to the site name.
		Will prompt for confirmation when a site path is not unique.
	passgo insertfile site-path file
		Add to your password store a file attached to a site. This site can optionally be a part
		of a group by prepending a group name and slash to the site name.
		Will prompt for confirmation when a site path is not unique.
	passgo rename site-path
		Rename an entry in the password vault.
	passgo edit site-path
		Change the password of a site in the vault.
	passgo generate length=24
		Prints a randomly generated password. The length of this password defaults
		to 24. If a very short length is specified, the generated password will be
		longer than desired and will contain a upper-case, lower-case, symbol, and
		digit.
	passgo find site-path
		Prints all sites that contain the site-path. Used to print just one group
		or all sites that contain a certain word in the group or name.
	passgo ls site-path
		An alias for the find subcommand.
	passgo remove site-path
		Remove a site from the password vault by specifying the entire site-path.
	passgo removefile site-path
		Remove a file from the vault by specifying the entire file-path.
	passgo rm site-path
		An alias for remove.
	passgo rmfile site-path
		An alias for removefile.
	passgo pull
		Pull will perform a git pull and sync the changes in the remote git
		repository with your local repo.
	passgo push
		Push will perform a git push to sync your changes with your remote
		git repository.
	passgo remote remote-url
		Remote is used to set the remote repository url. This is the repository
		that your sites will be pushed to and pulled from.
	passgo clone remote-url
		Clone will copy the remote url in to the .passgo directory in your
		home directory. It will fail if the directory already exists.
	passgo integrity
		Update the integrity hash of your password store if you are planning
		to manually push to the server.
	passgo usage
		Print this message!
	passgo version
		Print version information
`
)

func init() {
	flag.Parse()
	pc.AcceptInitialCodes()
	if userName != nil {
		pio.SetUser(*userName)
	}

	// Check to see if this user is under attack.
	pio.CheckAttackFile()
}

func main() {

	if pincode != nil {
		device.Reprogram(*pincode)
	}

	// Default behavior of just running the command is listing all sites.
	if len(flag.Args()) < 1 {
		show.ListAll()
		return
	}

	// subArgs is used by subcommands to retrieve only their args.
	subArgs := flag.Args()[1:]
	switch flag.Args()[0] {
	case "edit":
		path := getSubArguments(subArgs, ALLARGS)
		edit.Edit(path)
	case "ls", "find":
		path := getSubArguments(subArgs, ALLARGS)
		show.Find(path)
	case "generate":
		pwlenStr := getSubArguments(subArgs, 0)
		pwlen, err := strconv.Atoi(pwlenStr)
		if err != nil {
			pwlen = -1
		}
		pass := generate.Generate(pwlen)
		fmt.Println(pass)
	case "init":
		initialize.Init()
	case "erasepincode":
		device.Sudoer("$GOPATH/bin/pincodeeraser")

		/*
				// Maintenance only: must go
			case "acceptpincode":
				pinCode, err := device.AcceptPinCode()
				if err != nil {
					log.Println("no pin code found")
				} else {
					fmt.Printf("pinCode=%s\n", pinCode)
				}
				// Maintenance only
			case "acceptmasterkey":
				masterkey, err := device.AcceptMasterKey()
				if err != nil {
					log.Println("no master key found")
				} else {
					fmt.Printf("masterkey=%s\n", masterkey)
				}
				// Maintenance only
			case "initfromhardware":
				hwCodeRpb, hwCodeSdc, _ := device.GetHwCode()
				pinCode, _ := device.AcceptPinCode()
				fmt.Printf("hwCode={Rpb: %s, Sdc: %s}\n", hwCodeRpb, hwCodeSdc)
				fmt.Printf("pinCode=%s\n", pinCode)
				initialize.InitFromHardware(hwCodeRpb, hwCodeSdc, pinCode)
		*/
	case "insert":
		pathName := getSubArguments(subArgs, ALLARGS)
		insert.Password(pathName)
	case "insertpassword":
		allArgs := getSubArguments(subArgs, ALLARGS)
		argList := strings.Split(allArgs, " ")
		if len(argList) != 2 {
			printUsage()
			log.Fatalln("Incorrect args.")
		}
		pathName := argList[0]
		sitePass := argList[1]
		insert.GivenPassword(pathName, sitePass)
	case "integrity":
		pc.GetSitesIntegrity()
		sync.Commit(sync.IntegrityCommit)
	case "rm", "remove":
		path := getSubArguments(subArgs, ALLARGS)
		edit.RemovePassword(path)
	case "rename":
		path := getSubArguments(subArgs, ALLARGS)
		edit.Rename(path)
	case "help", "usage":
		printUsage()
	case "version":
		printVersion()
	case "pull":
		sync.Pull()
	case "push":
		sync.Push()
	case "remote":
		remote := getSubArguments(subArgs, 0)
		sync.Remote(remote)
	case "clone":
		repo := getSubArguments(subArgs, 0)
		sync.Clone(repo)
	case "show":
		path := getSubArguments(flag.Args(), 1)
		show.Site(path, *copyPass)
	case "insertfile":
		allArgs := getSubArguments(subArgs, ALLARGS)
		argList := strings.Split(allArgs, " ")
		if len(argList) != 2 {
			printUsage()
			log.Fatalln("Incorrect args.")
		}
		path := argList[0]
		filename := argList[1]
		insert.File(path, filename)
	case "rmfile", "removefile":
		path := getSubArguments(subArgs, ALLARGS)
		edit.RemoveFile(path)
	case "veracrypt_mount":
		//device.Sudoer("nohup sudo -u pi sh -c \"date && . /home/pi/veracrypt_mount_kf_silent.sh && date\" &")
		//device.SudoPi([]string{"sh -c \"date && . /home/pi/veracrypt_mount_kf_silent.sh && date\""})
		//device.SudoPi([]string{"source", "/home/pi/veracrypt_mount_kf_silent.sh"})
		device.Sudoer("/home/pi/veracrypt_mount_kf_silent.sh")
		//nohup sudo -u pi sh -c "date && . /home/pi/veracrypt_mount_kf_silent.sh && date" &

	case "veracrypt_unmount":
		//device.Sudoer("nohup sudo -u pi sh -c \". /home/pi/veracrypt_unmount_kf.sh\" &")
		device.SudoPi([]string{"sh -c \". /home/pi/veracrypt_unmount_kf.sh\""})
	default:
		log.Fatalf("%s\nInvalid Command %s", usage, os.Args[1])
	}
}

func printUsage() {
	fmt.Println(usage)
}
func printVersion() {
	fmt.Println(version)
}

// getSubArguments requires the list of subarguments and the
// argument number that you want returned. Non existent args
// will return an empty string. A negative arg index will
// return all arguments concatenated as one.
func getSubArguments(args []string, arg int) string {
	if len(args) == 0 {
		return ""
	}
	if arg < 0 {
		return strings.Join(args, " ")
	}
	if len(args) < arg+1 {
		log.Fatalf("Not enough args")
	}
	return args[arg]
}
