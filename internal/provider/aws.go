package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vogt/internal/secmem"
)

// AWS mints STS role sessions narrowed by a session policy. In proxy mode
// the session stays inside the broker and the proxy re-signs each request;
// in direct mode the agent gets the session and Vogt revokes it early by
// denying its SourceIdentity in an inline role policy.
//
// The master secret is JSON: {"access_key_id": "...", "secret_access_key":
// "..."} for an IAM user allowed to assume the capability's role and, for
// direct-mode revocation, to put and delete that role's inline policies.
type AWS struct {
	Client *http.Client
	// Endpoint returns the base URL for a service and region. Tests set it.
	Endpoint func(service, region string) string
	Now      func() time.Time
}

type awsScope struct {
	RoleArn   string   `json:"role_arn"`
	Region    string   `json:"region"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

type awsMaster struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

func (a *AWS) Name() string { return "aws" }

func (a *AWS) Guarantees() Guarantees {
	return Guarantees{MinDirectTTL: 15 * time.Minute, MaxDirectTTL: 12 * time.Hour, Revoke: RevokeDelayed}
}

func (a *AWS) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *AWS) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return http.DefaultClient
}

func (a *AWS) endpoint(service, region string) string {
	if a.Endpoint != nil {
		return a.Endpoint(service, region)
	}
	switch service {
	case "iam":
		return "https://iam.amazonaws.com"
	default:
		return fmt.Sprintf("https://%s.%s.amazonaws.com", service, region)
	}
}

func (a *AWS) scope(req Request) (awsScope, error) {
	var s awsScope
	if err := DecodeScope(req.Scope, &s); err != nil {
		return s, err
	}
	if !strings.HasPrefix(s.RoleArn, "arn:aws:iam::") || s.Region == "" || len(s.Actions) == 0 || len(s.Resources) == 0 {
		return s, errors.New("aws scope needs role_arn, region, actions and resources")
	}
	return s, nil
}

func (a *AWS) Permissions(req Request) ([]string, error) {
	s, err := a.scope(req)
	if err != nil {
		return nil, err
	}
	// AWS actions are checked against the forbidden list as they are,
	// for example "iam:*" or "sts:AssumeRole".
	return Sorted(s.Actions), nil
}

func (a *AWS) Mint(ctx context.Context, req Request, master []byte) (Credential, error) {
	s, err := a.scope(req)
	if err != nil {
		return nil, err
	}
	var m awsMaster
	if err := json.Unmarshal(master, &m); err != nil || m.AccessKeyID == "" || m.SecretAccessKey == "" {
		return nil, errors.New("aws master secret needs access_key_id and secret_access_key")
	}
	pol, _ := json.Marshal(map[string]any{
		"Version":   "2012-10-17",
		"Statement": []map[string]any{{"Effect": "Allow", "Action": s.Actions, "Resource": s.Resources}},
	})
	secs := int(req.TTL.Seconds())
	if secs < 900 {
		secs = 900 // the STS minimum
	}
	ident := "vogt-" + req.GrantID
	form := url.Values{
		"Action": {"AssumeRole"}, "Version": {"2011-06-15"},
		"RoleArn": {s.RoleArn}, "RoleSessionName": {ident}, "SourceIdentity": {ident},
		"DurationSeconds": {strconv.Itoa(secs)}, "Policy": {string(pol)},
	}
	var out struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string    `xml:"AccessKeyId"`
				SecretAccessKey string    `xml:"SecretAccessKey"`
				SessionToken    string    `xml:"SessionToken"`
				Expiration      time.Time `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	creds := AWSCreds{AccessKeyID: m.AccessKeyID, SecretAccessKey: m.SecretAccessKey}
	if err := a.query(ctx, creds, "sts", s.Region, form, &out); err != nil {
		return nil, fmt.Errorf("aws: assume role: %w", err)
	}
	c := out.Result.Credentials
	if c.AccessKeyID == "" || c.SessionToken == "" {
		return nil, errors.New("aws: empty role credentials")
	}
	sess, err := secmem.FromBytes([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if err != nil {
		return nil, err
	}
	cred := &awsCred{a: a, session: sess, region: s.Region, expires: c.Expiration, role: s.RoleArn, ident: ident}
	if req.Direct {
		// Keep the master only for direct grants: early revocation needs it.
		if cred.master, err = secmem.FromBytes(append([]byte(nil), master...)); err != nil {
			sess.Destroy()
			return nil, err
		}
	}
	return cred, nil
}

// query calls an AWS Query API (STS, IAM) and decodes the XML response.
func (a *AWS) query(ctx context.Context, c AWSCreds, service, region string, form url.Values, v any) error {
	body := form.Encode()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(service, region)+"/", strings.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	hr.Header.Set("User-Agent", UserAgent)
	hr.Host = hr.URL.Host
	signRegion := region
	if service == "iam" {
		signRegion = "us-east-1"
	}
	SignV4(hr, c, signRegion, service, sha256Hex([]byte(body)), a.now())
	resp, err := a.client().Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(raw) < 1<<20 {
		n, err := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s", resp.Status, truncate(raw, 300))
	}
	if v == nil {
		return nil
	}
	return xml.Unmarshal(raw, v)
}

func (a *AWS) Revoke(context.Context, []byte) error {
	// A handle alone cannot revoke: the role policy change needs the master
	// secret. Live direct grants revoke through the credential; after a
	// crash, the session simply runs to its STS expiry (at least 15 minutes).
	return nil
}

func (a *AWS) ProxyEnv(req Request, base, token string) []string {
	s, _ := a.scope(req)
	return []string{
		"AWS_ENDPOINT_URL=" + base,
		"AWS_SECRET_ACCESS_KEY=" + token,
		"AWS_REGION=" + s.Region,
		"AWS_SESSION_TOKEN=",
	}
}

type awsCred struct {
	a       *AWS
	session *secmem.Buffer // access key \0 secret \0 session token
	master  *secmem.Buffer // direct mode only
	region  string
	role    string
	ident   string
	expires time.Time
}

func (c *awsCred) creds() AWSCreds {
	f := strings.SplitN(string(c.session.Bytes()), "\x00", 3)
	return AWSCreds{AccessKeyID: f[0], SecretAccessKey: f[1], SessionToken: f[2]}
}

// Inject re-signs a request the proxy already verified. The proxy passes
// the client's service and region in X-Vogt-Aws-Scope.
func (c *awsCred) Inject(r *http.Request, rest string) error {
	region, service, ok := strings.Cut(r.Header.Get("X-Vogt-Aws-Scope"), "/")
	r.Header.Del("X-Vogt-Aws-Scope")
	if !ok || service == "" {
		return errors.New("aws: missing request scope")
	}
	if region != c.region && service != "iam" {
		return fmt.Errorf("aws: grant is for region %s", c.region)
	}
	if err := PointAt(r, c.a.endpoint(service, region), rest); err != nil {
		return err
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	for k := range r.Header {
		if lk := strings.ToLower(k); lk == "x-amz-date" || lk == "x-amz-security-token" {
			r.Header.Del(k)
		}
	}
	SignV4(r, c.creds(), region, service, payload, c.a.now())
	return nil
}

func (c *awsCred) Env() []string {
	cr := c.creds()
	return []string{
		"AWS_ACCESS_KEY_ID=" + cr.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + cr.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + cr.SessionToken,
		"AWS_REGION=" + c.region,
	}
}

func (c *awsCred) Handle() []byte     { return nil }
func (c *awsCred) Expires() time.Time { return c.expires }

// Revoke denies every action to this grant's SourceIdentity with an inline
// role policy, then deletes that policy once the session would have expired.
func (c *awsCred) Revoke(ctx context.Context) error {
	if c.master == nil {
		return nil // proxy mode: the session never left the broker
	}
	var m awsMaster
	if err := json.Unmarshal(c.master.Bytes(), &m); err != nil {
		return err
	}
	creds := AWSCreds{AccessKeyID: m.AccessKeyID, SecretAccessKey: m.SecretAccessKey}
	roleName := c.role[strings.LastIndexByte(c.role, '/')+1:]
	policyName := c.ident
	doc, _ := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect": "Deny", "Action": "*", "Resource": "*",
			"Condition": map[string]any{"StringEquals": map[string]string{"aws:SourceIdentity": c.ident}},
		}},
	})
	err := c.a.query(ctx, creds, "iam", "us-east-1", url.Values{
		"Action": {"PutRolePolicy"}, "Version": {"2010-05-08"},
		"RoleName": {roleName}, "PolicyName": {policyName}, "PolicyDocument": {string(doc)},
	}, nil)
	if err != nil {
		return fmt.Errorf("aws: deny source identity: %w", err)
	}
	cleanup := time.Until(c.expires) + time.Minute
	time.AfterFunc(cleanup, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c.a.query(ctx, creds, "iam", "us-east-1", url.Values{
			"Action": {"DeleteRolePolicy"}, "Version": {"2010-05-08"},
			"RoleName": {roleName}, "PolicyName": {policyName},
		}, nil)
	})
	return nil
}

func (c *awsCred) Wipe() {
	c.session.Destroy()
	// The master stays until the cleanup above has run.
	if c.master != nil {
		m := c.master
		time.AfterFunc(time.Until(c.expires)+2*time.Minute, m.Destroy)
	}
}
