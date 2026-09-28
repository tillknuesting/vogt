package daemon

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"vogt/internal/policy"
	"vogt/internal/proxy"
	"vogt/internal/vault"
)

const (
	fileCACert = "ca.crt"
	fileCAKey  = "ca.key"
)

// policyHosts lists every host the policy allows TLS interception for.
func policyHosts(p *policy.Policy) []string {
	var hosts []string
	for _, c := range p.Capabilities {
		for _, h := range c.Hosts {
			if !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
	}
	slices.Sort(hosts)
	return hosts
}

// ensureCA loads the interception CA, or makes a new one when the policy's
// hosts changed, so the CA never covers more than the policy does.
func (d *Daemon) ensureCA(p *policy.Policy) {
	hosts := policyHosts(p)
	if len(hosts) == 0 {
		d.setCA(nil)
		return
	}
	certPEM, err1 := os.ReadFile(d.state(fileCACert))
	keyPEM, err2 := os.ReadFile(d.state(fileCAKey))
	if err1 == nil && err2 == nil {
		if ca, err := proxy.ParseCA(certPEM, keyPEM); err == nil && slices.Equal(ca.Hosts(), hosts) {
			d.setCA(ca)
			return
		}
	}
	ca, err := proxy.NewCA(hosts)
	if err != nil {
		d.log.Error("cannot create interception CA", "err", err)
		d.setCA(nil)
		return
	}
	c, k, err := ca.PEM()
	if err == nil {
		err = vault.WriteFileAtomic(d.state(fileCAKey), k, 0o600)
	}
	if err == nil {
		err = vault.WriteFileAtomic(d.state(fileCACert), c, 0o644)
	}
	clear(k)
	if err != nil {
		d.log.Error("cannot store interception CA", "err", err)
	}
	d.setCA(ca)
	d.Audit("ca.created", map[string]string{"hosts": fmt.Sprint(hosts)})
}

func (d *Daemon) setCA(ca *proxy.CA) {
	d.mu.Lock()
	d.ca = ca
	d.mu.Unlock()
}

func (d *Daemon) currentCA() *proxy.CA {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ca
}

// CACertPEM returns the interception CA certificate for agents to trust.
func (d *Daemon) CACertPEM() ([]byte, error) {
	ca := d.currentCA()
	if ca == nil {
		return nil, errNoCA
	}
	c, _, err := ca.PEM()
	return c, err
}

var errNoCA = errors.New("no interception CA: no capability in the policy lists hosts")
