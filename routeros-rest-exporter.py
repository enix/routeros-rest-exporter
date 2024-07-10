#!/usr/bin/env python
# coding: utf-8
from argparse import ArgumentParser
import sys
import logging
from signal import signal, SIGTERM

from time import sleep, time
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import yaml
from prometheus_client import start_http_server
from prometheus_client import Counter, Gauge, Enum


PROM_PREFIX = "routeros_"  # Every metric name will be prefixed with this


logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def terminate(*_):  # pylint: disable=missing-function-docstring
    logger.info("Received SIGTERM, exiting.")
    sys.exit(0)


def get_metric_prom_name(api_path, api_name):
    "From the API path, and the metric name inside the API, return a suitable name for Prometheus"
    return PROM_PREFIX + api_path.replace("/", "_").replace("-", "_") + "_" + api_name.replace("-", "_")


def main():  # pylint: disable=missing-function-docstring
    signal(SIGTERM, terminate)

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

    interval = int(config["global"]["interval"])
    prom_port = int(config["global"]["listen_port"])
    custom_host_labels = config["global"]["custom_host_labels"]

    # These are the metadata (i.e. connection parameters, host labels, etc.) that can either be defined (in the config)
    # in the defaults, or in each target
    defaultable_parameters = [
        "username",
        "password_file",
        "password",
        "port",
        "allow_insecure",
        "timeout",
    ] + custom_host_labels

    # These are the host labels, i.e. what target metadata will be exposed to prometheus
    host_labels = ["hostname", "name"] + custom_host_labels

    # Build target listing, with their connections params and metadata, filling defaults if needed
    targets = []
    for target_config in config["targets"]:
        t = {}  # pylint: disable=invalid-name
        target_name = target_config["name"]
        logger.info("Building parameters and metadata for %s", target_name)
        t["name"] = target_name

        t["hostname"] = target_config.get("hostname", target_name)

        for parameter in defaultable_parameters:
            try:
                if (value := target_config.get(parameter)) is None:
                    value = config["defaults"][parameter]
                    logger.debug(
                        "%s : setting %s from defaults", target_name, parameter
                    )
                t[parameter] = value

            except KeyError as exc:
                _, exc_value, _ = sys.exc_info()
                if str(exc_value) not in ["'password'", "'password_file'"]:
                    # Password and password file will be handled separately since one can be unset if the other is set
                    raise ValueError(
                        f"You need to set the config attribute {exc_value}, on the target {target_name} or in the defaults"
                    ) from exc

        if "password" not in t:
            if "password_file" in t:
                with open(t["password_file"], "r", encoding="utf-8") as file:
                    t["password"] = file.read().splitlines()[0]
            else:
                raise ValueError(
                    f'You need to set either the config attributes "password" or "password_file", on the target {target_name} or in the defaults'
                )

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

            if metric_type == "gauge" or metric_type == "mapping":
                exported_metrics[metric_name] = Gauge(
                    metric_name,
                    f"Mikrotik RouterOS metric '{metric['name']}' under '{path}'",
                    labelnames=host_labels + normalized_labels,
                )
            elif metric_type == "enum":
                exported_metrics[metric_name] = Enum(
                    metric_name,
                    f"Mikrotik RouterOS metric '{metric['name']}' under '{path}'",
                    labelnames=host_labels + normalized_labels,
                    states=metric["enum"],
                )

    # This will hold each set of label:value PREVIOUSLY KNOWN for each metric. At each poll cycle, it will be compared
    # with the retrieved label:value set, in order to remove the no-longer-valid ones.
    # The goal is to clear metrics for removed FW rules, interfaces, etc.
    # For now, initialize it with the metrics names. It is done before the initialization of "api_unreachable" by design
    # so that it is never cleared.
    labelsets_known = {key: [] for key in exported_metrics}

    # Add one to check for API reachability
    exported_metrics[PROM_PREFIX + "api_unreachable"] = Counter(
        PROM_PREFIX + "api_unreachable", "Number of failed API requests", host_labels
    )

    # Let's roll baby !
    logger.info("Starting the HTTP server on port %s", prom_port)
    start_http_server(prom_port)

    # Fetch metrics from routers
    while True:

        start_time = time()

        # Same as labelsets_known but will contain only labelsets retrived during this poll cycle
        labelsets_current = {key: [] for key in exported_metrics}

        for target in targets:

            logger.info("Starting polling for %s", target["name"])

            # Extract host-level labels with their values
            target_labels = {}
            for label in host_labels:
                target_labels[label] = target[label]

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
                for index, data in enumerate(resp):

                    # Extract label values such as cpu names, comments, etc. depending on
                    # which API endpoint we are getting data from.
                    extracted_labels = target_labels.copy()
                    for label in endpoint.get("labels", []):
                        # If we have a label name more suitable for prom, use it
                        label_prom_name = label.get("prom_name", label["name"])

                        special = label.get("special")  # Is this a "meta-label" ?
                        if special == "index":
                            extracted_labels[label_prom_name] = index
                        else:
                            # If the label value is not present in the API response, default to ""
                            extracted_labels[label_prom_name] = data.get(
                                label["name"], ""
                            )

                    # Extract metrics and update the corresponding prom Gauge
                    for metric in endpoint["metrics"]:
                        metric_name = get_metric_prom_name(path, metric["name"])
                        # Default metric type is a Gauge
                        metric_type = metric.get("type", "gauge")

                        # If the item does not contain our desired metric, just skip it
                        # E.g. the default IPSEC policy does not have phase 2 count
                        if metric["name"] not in data:
                            continue

                        # Magic happens here, update prometheus gauge or enum depending on the metric type :
                        value = data[metric["name"]]
                        if metric_type == "gauge":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).set(value)
                        elif metric_type == "enum":
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).state(value)
                        elif metric_type == "mapping":
                            mapped_value = metric["mapping"].get(value)
                            if mapped_value is None:
                                logger.error(
                                    "Unknown mapping for %s - %s from %s : got '%s' which is not in the mappings",
                                    path,
                                    metric["name"],
                                    target["name"],
                                    value,
                                )
                                continue
                            exported_metrics[metric_name].labels(
                                **extracted_labels
                            ).set(mapped_value)

                        labelsets_current[metric_name].append(extracted_labels)

            logger.info("Finished polling %s", target["name"])

        # Compare labelsets retrieved during this cycle to labelsets already known

        # First, check that each previously-known labelset is still valid. If not, clear it.
        for metric_name, labelsets in labelsets_known.items():
            for known_labelset in labelsets:
                if known_labelset not in labelsets_current[metric_name]:
                    logger.info(
                        "Removing labelset %s for metric %s",
                        known_labelset,
                        metric_name,
                    )
                    # So long, Bowser !
                    exported_metrics[metric_name].remove(*known_labelset.values())
                    labelsets_known[metric_name].remove(known_labelset)

        # Then, add the newly retrieved labelsets to the known ones for the next cycle
        for metric_name, labelsets in labelsets_current.items():
            for current_labelset in labelsets:
                if current_labelset not in labelsets_known[metric_name]:
                    labelsets_known[metric_name].append(current_labelset)

        end_time = time()
        elapsed_time = int(end_time - start_time)
        if (sleep_time := interval - elapsed_time) < 0:
            sleep_time = 0

        logger.info(
            "Polling finished for all devices. It took %s secs, so going to sleep for %s secs",
            elapsed_time,
            sleep_time,
        )
        sleep(sleep_time)


if __name__ == "__main__":
    main()
