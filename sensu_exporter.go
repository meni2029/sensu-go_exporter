package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	timeout       = flag.Duration("timeout", 3000, "Timeout in nanoseconds for the API request")
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
	username = flag.String(
		"username", "admin", "Username for authentication")
)

type SensuEvent struct {
	Entity SensuEntity
	Check  SensuCheck
}

type SensuCheck struct {
	Duration float64
	Executed int64
	//Output      string
	Status   int
	Issued   int64
	Interval int
	Metadata SensuMetadata
	State    string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
}

type SensuMetadata struct {
	Name string
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

	results := c.getEvents()
	for i, result := range results {
		log.Debugln("...", fmt.Sprintf("%d, %v, %v", i, result.Check.Metadata.Name, result.Check.Status))
		// in Sensu, 0 means OK
		// in Prometheus, 1 means OK
		status := 0.0
		if result.Check.Status == 0 {
			status = 1.0
		} else {
			status = 0.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.CheckStatus,
			prometheus.GaugeValue,
			status,
			result.Entity.Metadata.Name,
			result.Check.Metadata.Name,
		)
	}
}

func (c *SensuCollector) getEvents() []SensuEvent {
	log.Debugln("Sensu API URL", c.apiUrl)
	events := []SensuEvent{}
	err := c.getJson(c.apiUrl+"/api/core/v2/namespaces/default/events", &events)
	if err != nil {
		log.Errorln("Query Sensu failed.", fmt.Sprintf("%v", err))
	}
	return events
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

func NewSensuCollector(apiUrl string, username string, password string, cli *http.Client) *SensuCollector {
	sc := &SensuCollector{
		cli:    cli,
		apiUrl: apiUrl,
		CheckStatus: prometheus.NewDesc(
			"sensu_check_status",
			"Sensu Check Status(1:Up, 0:Down)",
			[]string{"client", "check_name"},
			nil,
		),
	}
	err := sc.authenticate(username, password)
	if err != nil {
		log.Infoln(err)
	}
	return sc
}

func main() {
	flag.Parse()

	password := os.Getenv("SENSU_PASSWORD")
	collector := NewSensuCollector(*apiUrl, *username, password, &http.Client{
		Timeout: *timeout,
	})
	fmt.Println(collector.cli.Timeout)
	prometheus.MustRegister(collector)
	metricPath := "/metrics"
	http.Handle(metricPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(metricPath))
	})
	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
