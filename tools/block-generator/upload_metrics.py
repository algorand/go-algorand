from datadog import initialize
from datadog import api

options = {
        'api_key': os.getenv('DATADOG_API_KEY'),
        'app_key': os.getenv('DATADOG_APP_KEY')
    }

parser = argparse.ArgumentParser(description='Change prefix of files matching a pattern')
parser.add_argument('-performance-metrics-report', required=True, help='the report created by the block generator')
parser.add_argument('-conduit-version', required=True, help='Release version or the commit hash of the Conduit binary used during the performance test')
args = parser.parse_args()


def parseReport(report):
    with open(report) as f:
       for line in f:
           print line



if __name__ == '__main__':
    parseReport(args.performance_metrics_report)
    tags:= ["conduit_version: "+args.conduit_version, "duration: 1_hour", "scenario:mixed"]
    transactions_per_block_avg=0
    # api.Metric.send(metric = transactionsPerBlockAvgMetricName, points = transactions_per_block_avg, tags = tags)