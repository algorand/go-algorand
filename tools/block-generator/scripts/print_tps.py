import os
import argparse

TXN_PER_BLOCK = 5000
TXN_PER_BLOCK_SM = 100
TXN_PER_BLOCK_JUMBO = 25000

parser = argparse.ArgumentParser(description="Parse block TPS from reports")
parser.add_argument(
    "-d",
    "--perf-report-dir",
    required=False,
    dest="dir",
    help="report directory created by the block generator",
)

parser.add_argument(
    "-c",
    "--conduit-version",
    required=False,
    dest="conduit_version",
    help="Release version or the commit hash of the Conduit binary used during the performance test",
)

parser.add_argument(
    "-s" "--database-description",
    required=False,
    dest="database_description",
    help="A short description of the database state used for the performance test",
)

args = parser.parse_args()


def parse_report(report):
    data = dict()
    with open(report) as f:
        for line in f:
            tag, value = line.split(":")
            data[tag] = value if tag == "scenario" else float(value)
    return data


def pretty_print(data):
    table_header = (
        f"Scenario,Conduit_Version,{args.database_description}"
    )
    print(table_header)
    for d in data:
        scenario = d["scenario"].split("config.")[1]
        scenario_parsed = scenario.split(".yml")[0]
        txn_per_block = TXN_PER_BLOCK
        if "sm" in scenario:
            txn_per_block = TXN_PER_BLOCK_SM
        elif "jumbo" in scenario:
            txn_per_block = TXN_PER_BLOCK_JUMBO

        printed_scenario = (
            f"{scenario_parsed}({txn_per_block})"
        )
        print(
            f"{printed_scenario},{args.conduit_version},{d['final_overall_transactions_per_second']:.2f}"
        )


if __name__ == "__main__":
    data_list = []
    for f in os.listdir(args.dir):
        if f.endswith(".report"):
            report_data = parse_report(args.dir + f)
            data_list.append(report_data)
    pretty_print(data_list)
