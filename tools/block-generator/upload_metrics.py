from datadog import initialize
from datadog import api
import os
import argparse

parser = argparse.ArgumentParser(description="Upload performance metrics to Datadog")
parser.add_argument(
    "-f", "--perf-report", required=True, help="Report created by the block generator"
)
parser.add_argument(
    "-c",
    "--binary-version",
    required=True,
    help="Release version or the commit hash of the Conduit binary used during the performance test",
)
args = parser.parse_args()

data = dict()


def parseReport(report):
    with open(report) as f:
        for line in f:
            tag, value = line.split(":")
            data[tag] = float(value)
    f.close()


if __name__ == "__main__":
    print("initializing datadog")
    options = {
        "api_key": os.getenv("DATADOG_API_KEY"),
        "app_key": os.getenv("DATADOG_APP_KEY"),
    }
    initialize(**options)
    parseReport(args.perf_report)
    tags = [
        f"conduit_version: {args.binary_version}",
        f'duration: {str(data["test_duration_seconds"])}s',
        "scenario: mixed",
    ]
    transactionsPerBlockAvgMetricName = (
        "conduit.perf.final_overall_transactions_per_second"
    )
    tps = data["final_overall_transactions_per_second"]
    api.Metric.send(metric=transactionsPerBlockAvgMetricName, points=tps, tags=tags)
    print("uploaded metrics")
