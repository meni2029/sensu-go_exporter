# Sensu Go Exporter

A Prometheus exporter for Sensu Go.

A fork form legacy Sensu exporter (written by @reachlin) and sensu-go port (written by @qvicksilver)

This app. will export Sensu check status as Prometheus metrics. So previous Sensu checks can be integrated into Prometheus.

To run it:

```bash
make
./sensu-go_exporter [flags]
```

## Flags

```
$ ./sensu_exporter --help
Usage of ./sensu-go_exporter:
  -api string
        URL to Sensu API. (default "http://localhost:8080")
  -authfile string
        Read password from file. It not set, password is taken from environment variable SENSU_PASSWORD
  -insecure
        Client do not verify the server's certificate chain and host name. 
                        If used, crypto/tls accepts any certificate presented by the server and any host name in that certificate. 
                        In this mode, TLS is susceptible to machine-in-the-middle attacks unless custom verification is used. 
                        This should be used only for testing or in combination with VerifyConnection or VerifyPeerCertificate.
  -listen string
        Address to listen on for serving Prometheus Metrics. (default ":9251")
  -loglevel string
        Log level: Debug, Info, Warn, Error, Fatal (default "Info")
  -timeout duration
        Timeout for the API request (default 2s)
  -username string
        Username for authentication (default "admin")
```

## Exported Metrics
| Metric | Meaning | Labels |
| ------ | ------- | ------ |
| sensu_check_status | Check results in a metric vector, status 1 means OK | sensu_namespace, entity_name, check_name, last_ok_sec, occurrences, occurrences_watermark, check_is_silenced, check_state, check_status, check_proxy_entity_name |


### Docker [![Docker Pulls](https://img.shields.io/docker/pulls/meni2029/sensu-go_exporter.svg?maxAge=604800)][hub]

To run the sensu exporter as a Docker container, run:

```bash
docker run -e SENSU_PASSWORD=$(cat /file/with/password) -p 9251:9251 meni2029/sensu-go_exporter:v1.1.0 --api="http://sensu_host:4567"
```

[hub]: https://hub.docker.com/r/meni2029/sensu-go_exporter/
