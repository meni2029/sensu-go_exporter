package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

var (
	timeout       = flag.Duration("timeout", 2*time.Second, "Timeout for the API request")
	listenAddress = flag.String(
		// exporter port list:
		// https://github.com/prometheus/prometheus/wiki/Default-port-allocations
		"listen", ":9251",
		"Address to listen on for serving Prometheus Metrics.",
	)
	apiUrl = flag.String(
		"api", "http://localhost:8080",
		"URL to Sensu API.",
	)
	insecure = flag.Bool(
		"insecure", false,
		`Client do not verify the server's certificate chain and host name. 
		If used, crypto/tls accepts any certificate presented by the server and any host name in that certificate. 
		In this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used. 
		This should be used only for testing or in combination with VerifyConnection or VerifyPeerCertificate.`,
	)
	username = flag.String(
		"username", "admin", "Username for authentication")
	authfile = flag.String("authfile", "", "Read password from file. It not set, password is taken from environment variable SENSU_PASSWORD")
	logLevel = flag.String("loglevel", "Info", "Log level: Debug, Info, Warn, Error, Fatal")
)

type SensuNamespaces struct {
	Name string
}

type SensuEvent struct {
	Entity   SensuEntity
	Check    SensuCheck
	Metadata SensuMetadata
}

type SensuCheck struct {
	Duration              float64
	Executed              int64
	Status                int
	Issued                int64
	Interval              int
	Metadata              SensuMetadata
	State                 string
	Last_ok               int64
	Occurrences           int
	Occurrences_watermark int
	Is_silenced           bool
	Proxy_entity_name     string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
}

type SensuMetadata struct {
	Name      string
	Namespace string
}

type SensuEntity struct {
	Metadata SensuMetadata
}

// BEGIN: Class SensuCollector
type SensuCollector struct {
	apiUrl      string
	mutex       sync.RWMutex
	cli         *http.Client
	CheckStatus *prometheus.Desc
	token       *Token
}

func (c *SensuCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.CheckStatus
}

func (c *SensuCollector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock() // To protect metrics from concurrent collects.
	defer c.mutex.Unlock()

	var results []SensuEvent
	namespaces := c.getNamespaces()
	for _, namespace := range namespaces {
		results = append(results, c.getEvents(namespace.Name)...)
	}

	for i, result := range results {
		log.Debugln("...", fmt.Sprintf("%d, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v, %v", i, result.Entity.Metadata.Namespace, result.Entity.Metadata.Name, result.Check.Metadata.Name, result.Check.Issued, result.Check.Last_ok, result.Check.Occurrences, result.Check.Occurrences_watermark, result.Check.Is_silenced, result.Check.State, result.Check.Status, result.Check.Proxy_entity_name))
		// in Sensu, 0 means OK
		// in Prometheus, 1 means OK
		status := 0.0
		if result.Check.Status == 0 {
			status = 1.0
		} else {
			status = 0.0
		}
		last_ok_sec := ""
		if result.Check.Last_ok != 0 {
			last_ok_sec = strconv.FormatInt(result.Check.Issued-result.Check.Last_ok, 10)
		}
		if result.Check.Status == 0 {
			last_ok_sec = "0"
		}

		ch <- prometheus.MustNewConstMetric(
			c.CheckStatus,
			prometheus.GaugeValue,
			status,
			result.Entity.Metadata.Namespace,
			result.Entity.Metadata.Name,
			result.Check.Metadata.Name,
			last_ok_sec,
			strconv.Itoa(result.Check.Occurrences),
			strconv.Itoa(result.Check.Occurrences_watermark),
			strconv.FormatBool(result.Check.Is_silenced),
			result.Check.State,
			strconv.Itoa(result.Check.Status),
			result.Check.Proxy_entity_name,
		)
	}
}

func (c *SensuCollector) getEvents(namespace string) []SensuEvent {
	log.Debugln("Sensu API URL", c.apiUrl)
	events := []SensuEvent{}
	err := c.getJson(c.apiUrl+"/api/core/v2/namespaces/"+namespace+"/events", &events)
	if err != nil {
		log.Errorln("Query Sensu failed.", fmt.Sprintf("%v", err))
	}
	return events
}

func (c *SensuCollector) getNamespaces() []SensuNamespaces {
	log.Debugln("Sensu API URL", c.apiUrl)
	namespaces := []SensuNamespaces{}
	err := c.getJson(c.apiUrl+"/api/core/v2/namespaces", &namespaces)
	if err != nil {
		log.Errorln("Query Sensu failed.", fmt.Sprintf("%v", err))
	}
	return namespaces
}

func (c *SensuCollector) getJson(url string, obj interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+c.token.AccessToken)
	resp, err := c.cli.Do(req)
	if resp.StatusCode == 401 {
		c.refreshToken()
		req, err = http.NewRequest("GET", url, nil)
		req.Header.Add("Authorization", "Bearer "+c.token.AccessToken)
		resp, err = c.cli.Do(req)
	}
	if err != nil {
		log.Errorln(err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(obj)
}

func (c *SensuCollector) authenticate(username string, password string) error {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req, err := http.NewRequest("GET", c.apiUrl+"/auth", nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := c.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&c.token)
	if err != nil {
		log.Error("Token creation error")
		return err
	}

	return nil
}

func (c *SensuCollector) refreshToken() error {
	payload := []byte(`{"refresh_token":"` + c.token.RefreshToken + `"}`)
	req, err := http.NewRequest("POST", c.apiUrl+"/auth/token", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+c.token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := c.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&c.token)
	if err != nil {
		return err
	}

	return nil
}

// END: Class SensuCollector

func NewSensuCollector(apiUrl string, username string, password string, cli *http.Client) (*SensuCollector, error) {
	sc := &SensuCollector{
		cli:    cli,
		apiUrl: apiUrl,
		CheckStatus: prometheus.NewDesc(
			"sensu_check_status",
			"Sensu Check Status(1:Up, 0:Down)",
			[]string{"sensu_namespace", "entity_name", "check_name", "last_ok_sec", "occurrences", "occurrences_watermark", "check_is_silenced", "check_state", "check_status", "check_proxy_entity_name"},
			nil,
		),
	}
	err := sc.authenticate(username, password)

	return sc, err
}

func main() {
	flag.Parse()
	log.Base().SetLevel(*logLevel)

	// manage password
	var password string
	if len(*authfile) > 0 {
		log.Debug("Read pasword from file:", *authfile)
		content, err := ioutil.ReadFile(*authfile)
		if err != nil {
			log.Fatal("Password could not be read from file:", err)
		}
		password = strings.TrimSuffix(string(content), "\n")
	} else {
		log.Debug("Read pasword from env var SENSU_PASSWORD")
		password = os.Getenv("SENSU_PASSWORD")
	}
	if len(password) == 0 {
		log.Fatal("Password empty")
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: *insecure}
	collector, err := NewSensuCollector(*apiUrl, *username, password, &http.Client{
		Timeout:   *timeout,
		Transport: customTransport,
	})
	if err != nil {
		log.Fatal("API connection error:", err)
	}
	log.Infoln("API timeout:", collector.cli.Timeout)
	prometheus.MustRegister(collector)
	metricPath := "/metrics"
	http.Handle(metricPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(metricPath))
	})
	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
