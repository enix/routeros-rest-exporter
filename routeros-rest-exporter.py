#!/usr/bin/env python
# coding: utf-8
from argparse import ArgumentParser
from sys import exc_info, stdout
import logging

from time import sleep
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import yaml
from prometheus_client import start_http_server
from prometheus_client import Counter, Gauge, Enum


PROM_PREFIX = "routeros_"  # Every metric name will be prefixed with this

PROM_PORT = 9100  # TCP port where the HTTP server should listen

HOST_LABELS = [  # Labels common to all metrics, extracted from the target
    "hostname",
    "name",
    "tenant",
]

# Config parameters and metadata that can either be set at target-level, or in the defaults
DEFAULTABLE_PARAMETERS = [
    "username",
    "password",
    "port",
    "allow_insecure",
    "timeout",
    "tenant",
]

INTERVAL = 300

logging.basicConfig(stream=stdout)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_metric_prom_name(api_path, api_name):
    "From the API path, and the metric name inside the API, return a suitable name for Prometheus"
    return PROM_PREFIX + api_path.replace("/", "_") + "_" + api_name.replace("-", "_")


def get_target_labels(target_definition):
    "Extract host-level labels (hostname, tenant, etc) from a target definition dict."
    target_labels = {}
    for label in HOST_LABELS:
        target_labels[label] = target_definition[label]
    return target_labels


def main():  # pylint: disable=missing-function-docstring
    parser = ArgumentParser(
        description="Launch a Prometheus Exporter exposing metrics from Mikrotik RouterOS devices via their REST API."
    )
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/routeros-rest-exporter/config.yaml",
        help="YAML config file containing targets and credentials",
    )
    parser.add_argument(
        "-e",
        "--endpoints",
        default="/etc/routeros-rest-exporter/api_endpoints.yaml",
        help="YAML config file containing API endpoints to query and what metrics to export",
    )

    args = parser.parse_args()

    # Disable unverified certificate warning. If we request a self-signed API, that's on purpose
    disable_warnings(InsecureRequestWarning)

    logging.info("Loading config file at %s", args.config)
    with open(args.config, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if config is None:
        raise ValueError(f"Config file {args.config} is empty")

    logging.info("Loading API endpoints file at %s", args.endpoints)
    with open(args.endpoints, "r", encoding="utf-8") as file:
        endpoints = yaml.safe_load(file)
    if endpoints is None:
        raise ValueError(f"API endpoints file {args.endpoints} is empty")

    # Build target listing, with their connections params and metadata, filling defaults if needed
    targets = []
    for target_config in config["targets"]:
        t = {}  # pylint: disable=invalid-name
        target_name = target_config["name"]
        logger.info("Building parameters and metadata for %s", target_name)
        t["name"] = target_name

        t["hostname"] = target_config.get("hostname", target_name)
        try:
            for parameter in DEFAULTABLE_PARAMETERS:
                if (value := target_config.get(parameter)) is None:
                    value = config["defaults"][parameter]
                    logger.debug(
                        "%s : setting %s from defaults", target_name, parameter
                    )
                t[parameter] = value

        except KeyError as exc:
            _, exc_value, _ = exc_info()
            raise ValueError(
                f"You need to set the config attribute {exc_value}, on the target {target_name} or in the defaults"
            ) from exc

        targets.append(t)

    exported_metrics = {}  # The prometheus gauges and counters will be stored here

    # Initialize prometheus metrics
    for path, endpoint in endpoints["endpoints"].items():
        # Normalize labels, i.e. translate the ones that need to be translated (because of a conflict for instance).
        # Those are the one with an attribute "prom_name" instead of just a "name"
        normalized_labels = [
            label.get("prom_name", label["name"])
            for label in endpoint.get("labels", [])
        ]

        # Create all metrics under the current API endpoint
        for metric in endpoint["metrics"]:
            metric_name = get_metric_prom_name(path, metric["name"])
            metric_type = metric.get("type", "gauge")  # Default metric type is a Gauge

            if metric_type == "gauge":
                exported_metrics[metric_name] = Gauge(
                    metric_name,
                    f"Mikrotik RouterOS metric '{metric['name']}' under '{path}'",
                    labelnames=HOST_LABELS + normalized_labels,
                )
            elif metric_type == "enum":
                exported_metrics[metric_name] = Enum(
                    metric_name,
                    f"Mikrotik RouterOS metric '{metric['name']}' under '{path}'",
                    labelnames=HOST_LABELS + normalized_labels,
                    states=metric["enum"],
                )

    # Add one to check for API reachability
    exported_metrics[PROM_PREFIX + "api_unreachable"] = Counter(
        PROM_PREFIX + "api_unreachable", "Number of failed API requests", HOST_LABELS
    )

    # Let's roll baby !
    logger.info("Starting the HTTP server on port %s", PROM_PORT)
    start_http_server(PROM_PORT)

    # Fetch metrics from routers
    while True:
        for target in targets:

            logger.info("Starting polling for %s", target["name"])

            # Extract host-level labels
            target_labels = get_target_labels(target)

            # Prepare the request parameters
            auth = (target["username"], target["password"])
            verify = not target["allow_insecure"]

            # Start the API calls
            for path, endpoint in endpoints["endpoints"].items():

                url = f"https://{target['hostname']}:{target['port']}/rest/{path}"
                logger.info("Polling %s", url)
                try:
                    resp = requests.get(
                        url, auth=auth, verify=verify, timeout=target["timeout"]
                    )
                    resp.raise_for_status()
                except Exception as exc:  # pylint: disable=broad-except
                    logger.error(exc)
                    logger.error(
                        "Error while requesting %s, skipping this target.",
                        target["name"],
                    )
                    exported_metrics[PROM_PREFIX + "api_unreachable"].labels(
                        **target_labels
                    ).inc()
                    break
                resp = resp.json()

                # If we are at a single endpoint (e.g. ip/ipsec/statistics), simulate a list for the rest of the processing
                if not isinstance(resp, list):
                    resp = [resp]

                # Loop through all the items (interfaces, cpus, firewall rules, etc)
                for data in resp:

                    # Extract labe values such as cpu names, comments, etc. depending on
                    # which API endpoint we are getting data from.
                    extracted_labels = target_labels.copy()
                    for label in endpoint.get("labels", []):
                        # If we have a label name more suitable for prom, use it
                        label_prom_name = label.get("prom_name", label["name"])
                        # If the label value is not present in the API response, default to ""
                        extracted_labels[label_prom_name] = data.get(label["name"], "")

                    # Extract metrics and update the corresponding prom Gauge
                    for metric in endpoint["metrics"]:
                        metric_name = get_metric_prom_name(path, metric["name"])
                        # Default metric type is a Gauge
                        metric_type = metric.get("type", "gauge")

                        # If the item does not contain our desired metric, just skip it
                        # E.g. the default IPSEC policy does not have phase 2 count
                        if metric["name"] not in data:
                            continue

                        value = data[metric["name"]]

                        if metric_type == "gauge":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).set(value)
                        elif metric_type == "enum":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).state(value)

            logger.info("Finished polling %s", target["name"])

        logger.info(
            "Polling finished for all devices, going to sleep for %s seconds", INTERVAL
        )
        sleep(INTERVAL)


if __name__ == "__main__":
    main()
