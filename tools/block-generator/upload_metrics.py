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


def parseReport(report):
    data = dict()
    with open(report) as f:
        for line in f:
            tag, value = line.split(":")
            if tag == "scenario":
                data[tag] = value
            else:
                data[tag] = float(value)
    f.close()
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
        data = parseReport(fp)
        tags = [
            f'conduit_version:{args.binary_version}',
            f'duration:{str(data["test_duration_seconds"])}s',
            f'scenario:{str(data["scenario"])}',
        ]
        transactionsPerBlockAvgMetricName = "conduit.perf.transactions_per_second"
        tps = data["final_overall_transactions_per_second"]
        api.Metric.send(metric=transactionsPerBlockAvgMetricName, points=tps, tags=tags)
    print("uploaded metrics")
