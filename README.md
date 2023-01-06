# RouterOS REST Exporter

[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Brought by Enix](https://img.shields.io/badge/Brought%20to%20you%20by-ENIX-%23377dff?labelColor=888&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAQAAAC1QeVaAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfkBAkQIg/iouK/AAABZ0lEQVQY0yXBPU8TYQDA8f/zcu1RSDltKliD0BKNECYZmpjgIAOLiYtubn4EJxI/AImzg3E1+AGcYDIMJA7lxQQQQRAiSSFG2l457+655x4Gfz8B45zwipWJ8rPCQ0g3+p9Pj+AlHxHjnLHAbvPW2+GmLoBN+9/+vNlfGeU2Auokd8Y+VeYk/zk6O2fP9fcO8hGpN/TUbxpiUhJiEorTgy+6hUlU5N1flK+9oIJHiKNCkb5wMyOFw3V9o+zN69o0Exg6ePh4/GKr6s0H72Tc67YsdXbZ5gENNjmigaXbMj0tzEWrZNtqigva5NxjhFP6Wfw1N1pjqpFaZQ7FAY6An6zxTzHs0BGqY/NQSnxSBD6WkDRTf3O0wG2Ztl/7jaQEnGNxZMdy2yET/B2xfGlDagQE1OgRRvL93UOHqhLnesPKqJ4NxLLn2unJgVka/HBpbiIARlHFq1n/cWlMZMne1ZfyD5M/Aa4BiyGSwP4Jl3UAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjAtMDQtMDlUMTQ6MzQ6MTUrMDI6MDDBq8/nAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIwLTA0LTA5VDE0OjM0OjE1KzAyOjAwsPZ3WwAAAABJRU5ErkJggg==)](https://enix.io)

A Prometheus exporter for Mikrotik's RouterOS that uses the recent REST API and can be easily extended to support more metrics.

## How does this compare to other Mikrotik RouterOS exporters ?

Unlike other exporters available, this exporter allows you to easily customize which data are queried on the target, and thus exported to Promeheus.

The goal is to cover specific use-cases where you need an obscure metric, and to reduce the load on routers by allowing you to remove unneeded queries.

Additionnaly, this exporter uses the more recent REST API and not Mikrotik's custom binary API. Therefore, the code do not depends on any client library other than Python's well-known `requests` to query a target.

## Usage

```
$ ./routeros-rest-exporter.py --help
usage: routeros-rest-exporter.py [-h] [-c CONFIG] [-e ENDPOINTS]

Launch a Prometheus Exporter exposing metrics from Mikrotik RouterOS devices via their REST API.

options:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        YAML config file containing targets and credentials
  -e ENDPOINTS, --endpoints ENDPOINTS
                        YAML config file containing API endpoints to query and what metrics to export
```

## Configuration

The exporter is configured using a YAML file. Here is an example :

```yaml
global:
  listen_port: 9100  # TCP port the exporter will bind to and expose the HTTP interface
  interval: 300  # Polling interval, in seconds
  custom_host_labels:  # Custom host-level labels, see below
    - tenant
    - role
defaults:
  username: prometheus  # The user to use to connect to the API
  password: supersecurep4ssw0rd  # The password to use to connect to the API
  password_file: /etc/routeros-rest-exporter/password  # File where the password will be retrieved. `password` takes precedence over this.
  port: 443  # HTTPS port where the routerOS API listens
  allow_insecure: false  # Allow self-signed API certificate
  timeout: 5  # API query timeout, in seconds
targets:  # List of Mikrotik RouterOS devices to query
  - name: router-1.example.com  # Name of the device
    hostname: 198.51.100.1  # IP or hostname to connect to. If absent, `name` will be used
    tenant: customer1  # Value of the custom host-level label `tenant`
    role: primary  # Value of the custom host-level label `role`
```

### Defaults

The following parameters can be defined at target level or in the `defaults` section :
  - `username`
  - `password`
  - `password_file`
  - `port`
  - `allow_insecure`
  - `timeout`

They are all mandatory.

### Custom host labels

This exporter supports adding arbitrary labels to metrics, with values identical for all metrics of a single host. The labels' names must be defined in `global.custom_host_labels`, and their values must be set either in each target or in the `defaults`.

Custom host labels is the appropriate place to add host metadata such as a `tenant`, or whether the target is a primary or secondary device when active-passive redundancy is used. This is useful when later designing alerting rules for instance.

## RouterOS configuration

Here is the required configuration to enter your RouterOS device. Please note that the `service` corresponding to the REST API used by this exporter is `www-ssl` and not the older `api` or `api-ssl`, which can be disabled.

The `www-ssl` service requires a TLS certificate. These commands generate a self-signed certificate. You should consider using a real one, but it is outside the scope of this documentation.

```
/user/group/add name=api policy=read,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!dude

/user/add name=prometheus password="CHANGEME" group=api

/certificate add name=LocalCA common-name=LocalCA key-usage=key-cert-sign,crl-sign
/certificate sign LocalCA
/certificate add name=Mikrotik common-name=Mikrotik key-usage=tls-server
/certificate sign ca=LocalCA Mikrotik
/certificate set trusted=yes LocalCA
/certificate set trusted=yes Mikrotik

/ip/service/set www-ssl certificate=Mikrotik disabled=no
```

## API endpoints and metrics

Queried API endpoints and their corresponding metrics are defined in the YAML files passed as `-e` or `--endpoints` (with a default in `/etc/routeros-rest-exporter/api_endpoints.yaml`).
The provided `api_endpoints.yaml` contains a decent starting set of metrics that can be easily customized if needed.

Each metric is defined as an element of the dictionary `endpoints`, as such :

```yaml
system/resource/cpu:  # RouterOS REST API HTTP endpoint
  metrics:  # values to retrieve from the REST response and to expose as prometheus metrics
    - name: load
    - name: disk
    - name: irq
  labels:  # values to retrieve from the REST response and to expose as metriclabels
    - name: cpu
```

Here is an exemple of the corresponding REST API response from a RouterOS device :

```
[{'.id': '*0', 'cpu': 'cpu0', 'disk': '0', 'irq': '31', 'load': '31'},
 {'.id': '*1', 'cpu': 'cpu1', 'disk': '0', 'irq': '30', 'load': '33'}]
```
And the corresponding exported prometheus metrics :

```
# HELP routeros_system_resource_cpu_load Mikrotik RouterOS metric 'load' under 'system/resource/cpu'
# TYPE routeros_system_resource_cpu_load gauge
routeros_system_resource_cpu_load{cpu="cpu0",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 31.0
routeros_system_resource_cpu_load{cpu="cpu1",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 33.0
# HELP routeros_system_resource_cpu_disk Mikrotik RouterOS metric 'disk' under 'system/resource/cpu'
# TYPE routeros_system_resource_cpu_disk gauge
routeros_system_resource_cpu_disk{cpu="cpu0",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 0.0
routeros_system_resource_cpu_disk{cpu="cpu1",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 0.0
# HELP routeros_system_resource_cpu_irq Mikrotik RouterOS metric 'irq' under 'system/resource/cpu'
# TYPE routeros_system_resource_cpu_irq gauge
routeros_system_resource_cpu_irq{cpu="cpu0",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 31.0
routeros_system_resource_cpu_irq{cpu="cpu1",hostname="198.51.100.1",name="router-1.example.com",role="primary",tenant="customer1"} 33.0
```

You can easily see how an API response looks like by starting a Python shell and querying a target like this :

```python
import requests; requests.get("https://198.51.100.1:443/rest/system/resource/cpu", auth=('user','pass'), verify=False, timeout=5).json()
```

Single-item API endpoints (such as `ip/ipsec/statistics`), i.e. response that do not take the form of a list (list of CPUs, list of interfaces...), are automatically handled. Internally, they are converted to a list with a single item. Metric-level labels may not be appropriate for these metrics since there is nothing to discriminate.

You can get more information on RouterOS' REST API in the [documentation](https://help.mikrotik.com/docs/display/ROS/REST+API).

### Metric types

Metrics can have different types, depending on what they represent, and how they should be exported to prometheus.

#### Gauge (default)

```yaml
system/resource:
  metrics:
    - name: free-hdd-space
      type: gauge
```

The default metric type, gauge, is suitable for a simple integer counter. It produces a prometheus metric of the same type.

#### Enum

```yaml
ip/ipsec/policy:
  metrics:
    - name: ph2-state
      type: enum
      enum:
        - established
        - expired
        - no-phase2
  labels:
    - name: .id
      prom_name: policy_id
    - name: dst-address
      prom_name: dst_address
    - name: src-address
      prom_name: src_address
```

Suitable for an API response with text values. Creates a metric of type "Enum", with fixed possible values defined in `enum`, effectively exposing one prometheus metric per possible value, one of whom has a value of `1.0` and the others `0.0`.

```
# HELP routeros_ip_ipsec_policy_ph2_state Mikrotik RouterOS metric 'ph2-state' under 'ip/ipsec/policy'
# TYPE routeros_ip_ipsec_policy_ph2_state gauge
routeros_ip_ipsec_policy_ph2_state{dst_address="10.1.0.0/16",hostname="198.51.100.1",name="router-1.example.com",policy_id="*1000000",routeros_ip_ipsec_policy_ph2_state="established",src_address="10.2.0.0/24"} 1.0
routeros_ip_ipsec_policy_ph2_state{dst_address="10.1.0.0/16",hostname="198.51.100.1",name="router-1.example.com",policy_id="*1000000",routeros_ip_ipsec_policy_ph2_state="expired",src_address="10.2.0.0/24"} 0.0
routeros_ip_ipsec_policy_ph2_state{dst_address="10.1.0.0/16",hostname="198.51.100.1",name="router-1.example.com",policy_id="*1000000",routeros_ip_ipsec_policy_ph2_state="no-phase2",src_address="10.2.0.0/24"} 0.0
```

#### Mapping

```yaml
  ip/ipsec/policy:
    metrics:
      - name: ph2-state
        type: mapping
        mapping:
          established: 0
          expired: 1
          no-phase2: 2
    labels:
      - name: .id
        prom_name: policy_id
      - name: dst-address
        prom_name: dst_address
      - name: src-address
        prom_name: src_address
```

Also suitable for API response with text value, maybe easier than an enum to integrate into a Grafana dashboard, creates one metric of type Gauge, where each possible value is represented by a different integer. These text-to-integer mappings are defined in `mapping`.

```
# HELP routeros_ip_ipsec_policy_ph2_state Mikrotik RouterOS metric 'ph2-state' under 'ip/ipsec/policy'
# TYPE routeros_ip_ipsec_policy_ph2_state gauge
routeros_ip_ipsec_policy_ph2_state{dst_address="10.1.0.0/16",hostname="198.51.100.1",name="router-1.example.com",policy_id="*1000000",src_address="10.2.0.0/24"} 0.0
```

### Labels

#### prom_name

```yaml
ip/firewall/nat:
  metrics:
    - name: bytes
  labels:
    - name: .id
      prom_name: rule_id
    - name: log-prefix
      prom_name: log_prefix
```

Sometimes API response items destined to be used as label values can have non explicit names (such as `.id` or `name`) and/or contain forbidden characters (such as `-`). In that case, you can specify a `prom_name` besides the label's `name` to be used as the label name in the exported metrics.

#### special: index

```yaml
ip/firewall/filter:
  metrics:
    - name: packets
  labels:
    - name: order
      special: index
```

This label is not derived from the API response's values, but the position of the item in the returned list. In this `ip/firewall/filter` example, it is used to denote the order of each firewalling rule (unfortunately, `.id` is not useful in this matter) as they are presented by the API (and as they are evaluated by RouterOS).

### API reachability metric

This exporter also generate one metric, `routeros_api_unreachable`, which is a counter of each time an HTTPS query was unsuccessful (regardless of the reason) on the target.

## Using docker

### Building an image

You can build and run a docker image of this exporter using the provided dockerfile. It will embed the `api_endpoints.yaml` present in the repository. You may also create a `config.yaml` file at the root of the repository if you want to embed a config into the image. Alternatively, you can provide a configuration file with another mechanisme (e.g. bind mount, Kubernetes configmap, etc.).

### Using automatically built images

Images available on the Docker Hub (`enix/routeros-rest-exporter`) and on Github Container Registry (`ghcr.io/enix/routeros-rest-exporter`) are autmatically built on each tagged version of this repository. They use the provided `api_endpoints.yaml` but do not embed any configuration.

To run it, you can use the provided `docker-compose.yaml` file, which mounts a `config.yaml` it expects to find alongside itself.

To start the latest version of the exporter in the background and immediately start displaying its log output :
```
docker compose pull
docker compose up -d && docker compose logs -f
```

To stop it :
```
docker compose down
```

Currently, the exporter cannot be configured using environment variables.