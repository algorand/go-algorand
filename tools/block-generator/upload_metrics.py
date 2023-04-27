from datadog import initialize
from datadog import api
import os
import argparse

parser = argparse.ArgumentParser(description="Upload performance metrics to Datadog")
parser.add_argument(
    "-f",
    "--perf-reports",
    required=True,
    action="store",
    dest="files",
    type=str,
    nargs="*",
    help="list of reports created by the block generator",
)
parser.add_argument(
    "-c",
    "--binary-version",
    required=True,
    help="Release version or the commit hash of the Conduit binary used during the performance test",
)
args = parser.parse_args()


def parse_report(report):
    data = dict()
    with open(report) as f:
        for line in f:
            tag, value = line.split(":")
            data[tag] = value if tag == "scenario" else float(value)
    return data


if __name__ == "__main__":
    print("initializing datadog")
    options = {
        "api_key": os.getenv("DATADOG_API_KEY"),
        "app_key": os.getenv("DATADOG_APP_KEY"),
    }
    initialize(**options)
    for fp in args.files:
        print(f"uploading metrics for {fp}")
        data = parse_report(fp)
        tags = [
            f"conduit_version:{args.binary_version}",
            f'duration:{data["test_duration_seconds"]}s',
            f'scenario:{data["scenario"]}',
        ]
        transactionsPerBlockAvgMetricName = "conduit.perf.transactions_per_second"
        tps = data["final_overall_transactions_per_second"]
        api.Metric.send(metric=transactionsPerBlockAvgMetricName, points=tps, tags=tags)
    print("uploaded metrics")
