print("===== STARTED RUNNING check_tests.py =====\n")

import json
import sys
import argparse
NUMBER_OF_NODES = 4

# Arguments parsing / help menu
parser = argparse.ArgumentParser(description='Verify test results for skipped tests and tests with multiple passes.')
parser.add_argument('tests_results_filepath', metavar='RESULTS_FILE',
    help='json format test results file path (e.g. /tmp/results/testresults.json)')
args = parser.parse_args()

# Go through the given file one json object at a time, and record into a dict
AllTestResults = {}
with open(args.tests_results_filepath) as f:
    for jsonObj in f:
        testDict = json.loads(jsonObj)
        if 'Test' not in testDict:
            continue
        
        fullTestName = testDict['Package'] + ' ' + testDict['Test']
        if fullTestName not in AllTestResults:
            AllTestResults[fullTestName] = {}
            AllTestResults[fullTestName]['ran'] = 0
            AllTestResults[fullTestName]['skipped_due_to_partitioning'] = 0
            # AllTestResults[fullTestName]['other_reasons'] = []

        # actions can be: output, run, skip, pass
        if 'pass' in testDict["Action"]:
            AllTestResults[fullTestName]['ran'] += 1
        elif 'Output' in testDict:
            if 'due to partitioning' in testDict['Output']:
                AllTestResults[fullTestName]['skipped_due_to_partitioning'] += 1
            # elif not any(x in testDict['Output']for x in ['--- SKIP', '=== RUN', '--- PASS', '=== PAUSE', '=== CONT']):
                # AllTestResults[fullTestName]['other_reasons'].append(testDict['Output'])

            

f.close()

# === Calculate results ===

# Sort and print messages with colored prefix
RED_TEXT_COLOR = "\033[0;31m"
GREEN_TEXT_COLOR = "\033[0;32m"
YELLOW_TEXT_COLOR = "\033[0;33m"
NORMAL_TEXT_COLOR = "\033[0;0m"
def printColor(message, color=NORMAL_TEXT_COLOR):
    print(f"{color}{message}{NORMAL_TEXT_COLOR}")

# Record error message for sys.exit(errorMessage)
errorMessage = ''

# Check for tests that ran multiple times
printColor("=========== RAN MULTIPLE TIMES ===================", YELLOW_TEXT_COLOR)
listOfMultipleRuns = []
for x in AllTestResults:
    if AllTestResults[x]['ran'] > 1:
        listOfMultipleRuns.append(x + " -- ran " + str(AllTestResults[x]['ran']) + " times. (Can probably be fixed by adding \"partitiontest.PartitionTest()\")")
countMultipleRuns = len(listOfMultipleRuns) 
if countMultipleRuns:
    printColor(f"The above {countMultipleRuns} tests ran multiple times:", RED_TEXT_COLOR)
    [printColor(f"{x}", RED_TEXT_COLOR) for x in sorted(listOfMultipleRuns)]
    printColor(f"The above {countMultipleRuns} tests ran multiple times:", RED_TEXT_COLOR)
else:
    printColor("All tests that ran, ran only once ... OK", GREEN_TEXT_COLOR)
printColor("==================================================\n", YELLOW_TEXT_COLOR)

# Check intentionally skipped tests
printColor("============= INTENTIONALLY SKIPPED ==============", YELLOW_TEXT_COLOR)
# countSkippedOther = sum([1 for x in AllTestResults if 'other_reasons' in AllTestResults[x] and len(AllTestResults[x]['other_reasons'])])
listOfSkippedIntentionally = []
[listOfSkippedIntentionally.append(x) for x in AllTestResults if (AllTestResults[x]['ran'] == 0 and AllTestResults[x]['skipped_due_to_partitioning'] < NUMBER_OF_NODES)]
countSkippedIntentionally = len(listOfSkippedIntentionally)
if countSkippedIntentionally:
    printColor(f"The following {countSkippedIntentionally} tests were skipped intentionally:", YELLOW_TEXT_COLOR)
    [printColor(f"{x} -- skipped intentionally (please double check)", YELLOW_TEXT_COLOR) for x in sorted(listOfSkippedIntentionally)]
    printColor(f"The above {countSkippedIntentionally} tests were skipped intentionally:", YELLOW_TEXT_COLOR)
else:
    printColor("No tests skipped intentionally.", GREEN_TEXT_COLOR)
printColor("==================================================\n", YELLOW_TEXT_COLOR)

# Check tests unintentionally (due to partition)
printColor("============= UNINTENTIONALLY SKIPPED ============", YELLOW_TEXT_COLOR)
listOfSkippedUnintentionally = []
[listOfSkippedUnintentionally.append(x) for x in AllTestResults if (AllTestResults[x]['ran'] == 0 and AllTestResults[x]['skipped_due_to_partitioning'] >= NUMBER_OF_NODES)]
countSkippedUnintentionally = len(listOfSkippedUnintentionally)
if countSkippedUnintentionally:
    printColor(f"{countSkippedUnintentionally} tests were skipped UNintentionally", RED_TEXT_COLOR)
    [printColor(f"{x} -- skipped UNintentionally. (due to partitiontest.PartitionTest() being called twice?)", RED_TEXT_COLOR) for x in sorted(listOfSkippedUnintentionally)]
    printColor(f"{countSkippedUnintentionally} tests were skipped UNintentionally.", RED_TEXT_COLOR)
    errorMessage += f"{countSkippedUnintentionally} tests were skipped UNintentionally";
else:
    printColor("No tests skipped UNintentionally (due to partitioning).", GREEN_TEXT_COLOR)
printColor("==================================================\n", YELLOW_TEXT_COLOR)

# === Summary ===
printColor("==================== SUMMARY =====================", YELLOW_TEXT_COLOR)
countUniqueTests = len(AllTestResults)
countTotalSkipped = countSkippedIntentionally + countSkippedUnintentionally
countRanTests = sum(1 for x in AllTestResults if AllTestResults[x]['ran'] > 0)

printColor(f"Saw {countUniqueTests} unique tests", GREEN_TEXT_COLOR if countUniqueTests != 0 else RED_TEXT_COLOR)
printColor(f"{countTotalSkipped} total skipped tests", GREEN_TEXT_COLOR if countTotalSkipped == 0 else YELLOW_TEXT_COLOR)
printColor(f"{countRanTests} tests ran", GREEN_TEXT_COLOR if countRanTests != 0 else RED_TEXT_COLOR)
printColor(f"{countSkippedIntentionally} tests were skipped intentionally. (They were probably disabled, please double check)", GREEN_TEXT_COLOR if countSkippedIntentionally == 0 else YELLOW_TEXT_COLOR)
printColor(f"{countSkippedUnintentionally} tests were skipped UNintentionally. (Due to partitioning multiple times? maybe due to partitiontest.PartitionTest() being called twice?)", GREEN_TEXT_COLOR if countSkippedUnintentionally == 0 else RED_TEXT_COLOR)
printColor(f"{countMultipleRuns} tests ran multiple times. (Can probably be fixed by adding \"partitiontest.PartitionTest()\")", GREEN_TEXT_COLOR if countMultipleRuns == 0 else RED_TEXT_COLOR)
printColor("==================================================\n", YELLOW_TEXT_COLOR)

print("===== FINISHED RUNNING check_tests.py =====")
sys.exit(0 if not errorMessage else errorMessage)
