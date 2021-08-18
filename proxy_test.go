package centrify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/suite"

	"github.com/centrify/platform-go-sdk/testutils"
)

const (
	// proxyDockerfile defines dockerfile used for testing proxy.
	proxyDockerfile = `FROM debian:10.9
RUN echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
RUN apt-get update && apt-get install -y \
	sudo iptables ca-certificates wget \
  && rm -rf /var/lib/apt/lists/*
RUN wget --no-check-certificate https://cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem
RUN mkdir -p /usr/local/share/ca-certificates/extra/ \
  && mv DigiCertGlobalRootCA.crt.pem /usr/local/share/ca-certificates/extra/DigiCertGlobalRootCA.crt.pem \
  && update-ca-certificates
`
)

type HTTPProxyTestSuite struct {
	testutils.CfyTestSuite
}

func (s *HTTPProxyTestSuite) SetupSuite() {
	t := s.T()
	s.LoadConfig()

	if s.Config.HTTPProxyURL == "" {
		t.Skip("HTTPProxyURL required for tests in this suite")
	}

	if os.Getenv("VAULT_PLUGINS_DIR") == "" {
		t.Skip("VAULT_PLUGINS_DIR required for tests in this suite")
	}
}

func (s *HTTPProxyTestSuite) TestHTTP_PROXYiptables() {
	t := s.T()
	s.RequiresVault()

	dockerDir := "./dockerdir"
	vaultPath := filepath.Join(dockerDir, "vault")
	dockerfilePath := filepath.Join(dockerDir, "Dockerfile")
	dockerEntryPath := filepath.Join(dockerDir, "entry.sh")

	err := os.Mkdir(dockerDir, 0755)
	if err != nil {
		t.Log("Directory already exists")
	}

	path, err := exec.LookPath("vault")
	if err != nil {
		t.Skip("vault is not in PATH")
	}

	bytesRead, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(vaultPath, bytesRead, 0755)
	if err != nil {
		t.Fatal(err)
	}

	dockerDirAbsolute, err := filepath.Abs(dockerDir)
	if err != nil {
		t.Fatal(err)
	}

	pluginsDir, err := filepath.Abs(os.Getenv("VAULT_PLUGINS_DIR"))
	if err != nil {
		t.Fatal(err)
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skip("Can't connect to Docker daemon")
	}

	u, err := url.Parse(s.Config.HTTPProxyURL)
	if err != nil {
		t.Log(err)
		t.Skip("Can't parse value of HTTPProxyURL")
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Log(err)
		t.Skip("No host specified")
	}

	tenantURL, err := url.Parse(s.Config.TenantURL)
	if err != nil {
		t.Log(err)
		t.Skip("Can't parse value of tenantURL")
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		t.Log(err)
		t.Skip("HTTP proxy server is unreachable")
	}
	var proxyIP string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			proxyIP = ip.String()
		}
	}

	err = ioutil.WriteFile(dockerfilePath, []byte(proxyDockerfile), 0666) //nolint:gosec
	if err != nil {
		log.Fatal(err)
	}

	entrypointFileContent := fmt.Sprintf(`#!/bin/bash
IP=$(/sbin/ip route | awk '/default/ { print $3 }') && \
iptables -I OUTPUT -j REJECT --reject-with icmp-net-unreachable && \
iptables -I OUTPUT -j ACCEPT -d 127.0.0.1 && \
iptables -I OUTPUT -j ACCEPT -d 0.0.0.0 && \
iptables -I OUTPUT -j ACCEPT -d 8.8.8.8 && \
iptables -I OUTPUT -j ACCEPT -d $IP && \
iptables -I OUTPUT -j ACCEPT -d %s && \
echo 'nameserver 8.8.8.8' >> /etc/resolv.conf && \
/workdir/vault server -dev -dev-root-token-id=root -log-level=debug -dev-plugin-dir=/plugins -dev-listen-address=0.0.0.0:$PORT`, proxyIP)

	if err := ioutil.WriteFile(dockerEntryPath, []byte(entrypointFileContent), 0777); err != nil {
		log.Fatal(err)
	}

	proxyURL := s.Config.HTTPProxyURL
	var proxyTests = []struct {
		envVariables []string
		expectsError bool
		port         string
	}{
		{envVariables: []string{"HTTPS_PROXY=" + proxyURL, "NO_PROXY=0.0.0.0"}, expectsError: false, port: "19999"},
		{envVariables: []string{"HTTP_PROXY=" + proxyURL, "NO_PROXY=0.0.0.0"}, expectsError: true, port: "11011"},
		{envVariables: []string{"NO_PROXY=0.0.0.0," + tenantURL.Host}, expectsError: true, port: "11015"},
		{envVariables: []string{"HTTPS_PROXY=" + proxyURL, "HTTP_PROXY=" + proxyURL, "NO_PROXY=0.0.0.0"}, expectsError: false, port: "11021"},
		{envVariables: []string{"NO_PROXY=0.0.0.0," + tenantURL.Host, "HTTP_PROXY=" + proxyURL}, expectsError: true, port: "11031"},
		{envVariables: []string{"NO_PROXY=0.0.0.0," + tenantURL.Host, "HTTPS_PROXY=" + proxyURL}, expectsError: true, port: "11041"},
	}
	for _, test := range proxyTests {
		test := test
		t.Run("dockertest"+test.port, func(t *testing.T) {
			t.Parallel()

			port := test.port
			portWithTCP := test.port + "/tcp"
			ports := map[docker.Port][]docker.PortBinding{
				docker.Port(portWithTCP): {{HostPort: test.port}},
			}

			runOptions := &dockertest.RunOptions{
				Privileged:   true,
				PortBindings: ports,
				DNS:          []string{"8.8.8.8"},
				Name:         "my-test-auth-image" + test.port,
				Mounts:       []string{pluginsDir + ":/plugins", dockerDirAbsolute + ":/workdir"},
				Env:          append(test.envVariables, "PORT="+test.port),
				WorkingDir:   "/workdir",
				ExposedPorts: []string{port + "/tcp"},
				Cmd:          []string{"bash", "./entry.sh"},
			}
			buildOptions := &dockertest.BuildOptions{
				ContextDir: dockerDir,
				Dockerfile: "Dockerfile",
			}
			resource, err := pool.BuildAndRunWithBuildOptions(buildOptions, runOptions,
				func(config *docker.HostConfig) {
					config.AutoRemove = true
					config.RestartPolicy = docker.RestartPolicy{
						Name: "no",
					}
				})
			if err != nil {
				log.Fatalf("Could not start resource: %s", err)
			}

			data := []byte(`path "centrify/*" {
capabilities = ["create", "update", "read", "delete",  "list"]
}`)
			err = ioutil.WriteFile("all_users", data, 0644)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Second)

			for _, command := range [][]string{
				{"login", "-no-store=true", "root"},
				{"auth", "enable", "centrify"},
				{
					"write",
					"auth/centrify/config",
					"service_url=" + s.Config.TenantURL,
					"client_id=" + s.Config.ClientID,
					fmt.Sprintf("client_secret=%s", s.Config.ClientSecret),
					"app_id=" + s.Config.AppID,
					"policies=all_users",
				},
				{"policy", "write", "all_users", "./all_users"},
			} {
				var stderr bytes.Buffer
				cmd := exec.Command("vault", command...)
				cmd.Env = os.Environ()
				cmd.Env = append(cmd.Env, "VAULT_ADDR=http://localhost:"+port)
				cmd.Env = append(cmd.Env, "VAULT_TOKEN=root")
				cmd.Stderr = &stderr
				output, err := cmd.Output()
				if err != nil {
					t.Log(string(output))
					t.Log(stderr.String())
					t.Error(err)
				}
			}
			cmdLogin := exec.Command(
				"vault",
				"login",
				"-format=json",
				"-no-store=true",
				"-method=centrify",
				fmt.Sprintf("username=%s", s.Config.PASuser.Username),
				fmt.Sprintf("password=%s", s.Config.PASuser.Password),
			)
			var stderrLogin bytes.Buffer
			cmdLogin.Env = os.Environ()
			cmdLogin.Env = append(cmdLogin.Env, "VAULT_ADDR=http://localhost:"+port)
			cmdLogin.Stderr = &stderrLogin
			output, err := cmdLogin.Output()

			if !test.expectsError {
				s.Assert().Nil(err)
			} else {
				s.Assert().NotNil(err)
			}
			if err != nil {
				t.Logf("%v: %s", err, stderrLogin.String())
				if err = pool.Purge(resource); err != nil {
					t.Fatalf("Could not purge resource: %s", err)
				}
				return
			}

			loginResponse := &authVaultLoginResponse{}
			err = json.Unmarshal(output, loginResponse)
			if err != nil {
				s.T().Fatal(err)
			}

			if err = pool.Purge(resource); err != nil {
				t.Fatalf("Could not purge resource: %s", err)
			}
		})

	}
	t.Cleanup(func() {
		err := os.RemoveAll(dockerDir)
		if err != nil {
			t.Log(err)
		}
		err = os.Remove("./all_users")
		if err != nil {
			t.Log(err)
		}
	})
}

func TestHTTPProxyTestSuite(t *testing.T) {
	suite.Run(t, new(HTTPProxyTestSuite))
}
