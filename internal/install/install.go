// Package install produces the service installation for Vogt: a dedicated
// system user, the state and socket directories, and a launchd or systemd
// unit that runs the daemon as that user. By default it only prints the
// plan; Apply carries it out and needs root.
package install

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// Options configure an installation.
type Options struct {
	GOOS       string // "darwin" or "linux"
	Binary     string // where the vogt binary is installed
	HumanUser  string // the account that runs agents and the helper
	ServiceUID int    // macOS: UID for the _vogt user (below 500)
	HelperApp  string // macOS: path to the helper app bundle's executable

	self string // the running binary, copied into place
}

// Paths are the fixed locations for an OS.
type Paths struct {
	State, Run, Unit, User, Group string
}

// PathsFor returns the locations used on goos.
func PathsFor(goos string) Paths {
	if goos == "darwin" {
		return Paths{
			State: "/var/db/vogt",
			Run:   "/Library/Application Support/Vogt/run",
			Unit:  "/Library/LaunchDaemons/dev.vogt.daemon.plist",
			User:  "_vogt", Group: "_vogt",
		}
	}
	return Paths{State: "/var/lib/vogt", Run: "/run/vogt", Unit: "/etc/systemd/system/vogt.service", User: "vogt", Group: "vogt"}
}

// Step is one action of the plan.
type Step struct {
	Desc    string
	Cmd     []string // run this command, or
	Path    string   // write Content to Path with Mode
	Content []byte
	Mode    os.FileMode
}

func (s Step) String() string {
	if s.Cmd != nil {
		return fmt.Sprintf("%s\n    $ %s", s.Desc, strings.Join(quoteAll(s.Cmd), " "))
	}
	return fmt.Sprintf("%s\n    write %s (mode %o, %d bytes)", s.Desc, s.Path, s.Mode, len(s.Content))
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " '\"$") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return out
}

// Plan returns the steps to install Vogt.
func Plan(o Options) ([]Step, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	o.self = self
	if o.HumanUser == "" || o.HumanUser == "root" {
		return nil, fmt.Errorf("install: name the human's account with --user")
	}
	if o.Binary == "" {
		o.Binary = "/usr/local/libexec/vogt/vogt"
	}
	p := PathsFor(o.GOOS)
	switch o.GOOS {
	case "darwin":
		return darwinPlan(o, p)
	case "linux":
		return linuxPlan(o, p)
	}
	return nil, fmt.Errorf("install: unsupported OS %s", o.GOOS)
}

func render(t string, data any) []byte {
	var b bytes.Buffer
	template.Must(template.New("").Parse(t)).Execute(&b, data)
	return b.Bytes()
}

const launchDaemon = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>dev.vogt.daemon</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Binary}}</string>
		<string>daemon</string>
		<string>--state</string><string>{{.P.State}}</string>
		<string>--run</string><string>{{.P.Run}}</string>
	</array>
	<key>UserName</key><string>{{.P.User}}</string>
	<key>GroupName</key><string>{{.P.Group}}</string>
	<key>Umask</key><integer>63</integer>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
	<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
	<key>StandardErrorPath</key><string>/Library/Logs/vogt.log</string>
</dict>
</plist>
`

const launchAgent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>dev.vogt.helper</string>
	<key>ProgramArguments</key>
	<array><string>{{.HelperApp}}</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
`

func darwinPlan(o Options, p Paths) ([]Step, error) {
	if o.ServiceUID == 0 {
		o.ServiceUID = 470
	}
	if o.ServiceUID >= 500 {
		return nil, fmt.Errorf("install: the service UID must be below 500")
	}
	if o.HelperApp == "" {
		o.HelperApp = "/Applications/Vogt Helper.app/Contents/MacOS/VogtHelper"
	}
	uid := fmt.Sprint(o.ServiceUID)
	data := struct {
		Options
		P Paths
	}{o, p}
	home := "/Users/" + o.HumanUser
	return []Step{
		{Desc: "Create the _vogt group", Cmd: []string{"dscl", ".", "-create", "/Groups/_vogt", "PrimaryGroupID", uid}},
		{Desc: "Create the _vogt user (no login shell, no home)", Cmd: []string{"dscl", ".", "-create", "/Users/_vogt", "UniqueID", uid}},
		{Desc: "", Cmd: []string{"dscl", ".", "-create", "/Users/_vogt", "PrimaryGroupID", uid}},
		{Desc: "", Cmd: []string{"dscl", ".", "-create", "/Users/_vogt", "UserShell", "/usr/bin/false"}},
		{Desc: "", Cmd: []string{"dscl", ".", "-create", "/Users/_vogt", "NFSHomeDirectory", "/var/empty"}},
		{Desc: "Let the human's account reach the sockets", Cmd: []string{"dseditgroup", "-o", "edit", "-a", o.HumanUser, "-t", "user", "_vogt"}},
		{Desc: "Install the binary, owned by root", Cmd: []string{"install", "-o", "root", "-g", "wheel", "-m", "0755", "-d", filepath.Dir(o.Binary)}},
		{Desc: "", Cmd: []string{"install", "-o", "root", "-g", "wheel", "-m", "0755", o.self, o.Binary}},
		{Desc: "State directory, readable only by _vogt", Cmd: []string{"install", "-o", p.User, "-g", p.Group, "-m", "0700", "-d", p.State}},
		{Desc: "Socket directory, reachable by the _vogt group", Cmd: []string{"install", "-o", p.User, "-g", p.Group, "-m", "0750", "-d", p.Run}},
		{Desc: "LaunchDaemon that runs the broker as _vogt", Path: p.Unit, Content: render(launchDaemon, data), Mode: 0o644},
		{Desc: "LaunchAgent that runs the Touch ID helper in the human's session", Path: home + "/Library/LaunchAgents/dev.vogt.helper.plist", Content: render(launchAgent, data), Mode: 0o644},
		{Desc: "", Cmd: []string{"chown", o.HumanUser, home + "/Library/LaunchAgents/dev.vogt.helper.plist"}},
		{Desc: "Start the broker", Cmd: []string{"launchctl", "bootstrap", "system", p.Unit}},
	}, nil
}

const systemdUnit = `[Unit]
Description=Vogt credential broker for AI agents
After=network.target

[Service]
ExecStart={{.Binary}} daemon --state {{.P.State}} --run {{.P.Run}}
User={{.P.User}}
Group={{.P.Group}}
StateDirectory=vogt
StateDirectoryMode=0700
RuntimeDirectory=vogt
RuntimeDirectoryMode=0750
UMask=0077
LimitCORE=0
LimitMEMLOCK=64M
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
SystemCallArchitectures=native
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

func linuxPlan(o Options, p Paths) ([]Step, error) {
	data := struct {
		Options
		P Paths
	}{o, p}
	return []Step{
		{Desc: "Create the vogt system user", Cmd: []string{"useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group", p.User}},
		{Desc: "Let the human's account reach the sockets", Cmd: []string{"usermod", "-a", "-G", p.Group, o.HumanUser}},
		{Desc: "Install the binary, owned by root", Cmd: []string{"install", "-o", "root", "-g", "root", "-m", "0755", "-D", o.self, o.Binary}},
		{Desc: "systemd unit with sandboxing", Path: p.Unit, Content: render(systemdUnit, data), Mode: 0o644},
		{Desc: "Start the broker", Cmd: []string{"systemctl", "enable", "--now", "vogt.service"}},
	}, nil
}

// Apply runs the plan. It needs root.
func Apply(steps []Step) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install: --apply needs root; run it with sudo")
	}
	for _, s := range steps {
		if s.Desc != "" {
			fmt.Println("==", s.Desc)
		}
		if s.Cmd != nil {
			c := exec.Command(s.Cmd[0], s.Cmd[1:]...)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("%s: %w", strings.Join(s.Cmd, " "), err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(s.Path, s.Content, s.Mode); err != nil {
			return err
		}
	}
	return nil
}
