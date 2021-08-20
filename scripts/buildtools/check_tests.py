import json
import sys

print("===== STARTED RUNNING check_tests.py =====")
if len(sys.argv) != 2:
    print("Wrong number of arguments passed. Please pass one argument: json format test results file path (e.g. /tmp/results/testresults.json)")
    sys.exit(1)
filepath = sys.argv[1]

# Go through the given file one json object at a time, and record into lists
total = set()
passedWDupes = []
partitionSkipped = set()
with open(filepath) as f:
    for jsonObj in f:
        testDict = json.loads(jsonObj)
        if 'Test' not in testDict:
            continue
        
        fullTestName = testDict['Package'] + ' ' + testDict['Test']
        total.add(fullTestName)
        # actions can be: output, run, skip, pass
        if 'pass' in testDict["Action"]:
            passedWDupes.append(fullTestName)
        if 'Output' in testDict and 'due to partitioning' in testDict['Output']:
            partitionSkipped.add(fullTestName)

f.close()

# === Calculate results ===

# Total seen (deduped)
# total

# Passed with duplicates (needed for checking which tests passed multiple times)
# passedWDupes

# Passed without duplicates (deduped)
passed = set(passedWDupes)

# Skipped at least once due to partition (deduped)
# partitionSkipped

# Skipped due to partition and never passed (deduped)
partitionSkippedNotPass = partitionSkipped - passed

# Skipped due to other reasons (deduped)
skippedNotPartition = total - passed.union(partitionSkipped)

# Total not passed (deduped)
notPassed = total - passed

# === Summary ===
print("==================================================")
print("Saw {} tests total".format(len(total)))
print("{} passed before dedup".format(len(passedWDupes)))
print("{} passed after dedup".format(len(passed)))
print("{} skipped total".format(len(notPassed)))
print("{} skipped due to partition".format(len(partitionSkippedNotPass)))
print("{} skipped for other reasons (Maybe on purpose)".format(len(skippedNotPartition)))
print("==================================================")

errorMessage = ''
# Check tests not passed due to partition
print("==================================================")
if len(partitionSkippedNotPass):
    print("{} tests didn't pass due to partition!!".format(len(partitionSkippedNotPass)))
    print("Here are the ones that didn't pass due to partition: ")
    print(*sorted(list(partitionSkippedNotPass)), sep = "\n")
    errorMessage += "FAIL ERROR: {} tests didn't pass due to partition!! (Scroll up to see which)\n".format(len(partitionSkippedNotPass))
else:
    print("No tests skipped due to partition.")
print("==================================================")

# Check tests not passed for other reasons
print("==================================================")
if len(skippedNotPartition):
    print("{} tests didn't pass due to other reasons (Maybe on purpose)".format(len(skippedNotPartition)))
    print("Here are the ones that didn't pass due to other reasons: ")
    print(*sorted(list(skippedNotPartition)), sep = "\n")
else:
    print("No tests skipped for other reasons.")
print("==================================================")

# Check for duplicates in the passed tests
print("==================================================")
if len(passedWDupes) != len(passed):
    testDuplicates = set([testName + " - " + str(passedWDupes.count(testName)) for testName in passedWDupes if passedWDupes.count(testName) > 1])
    print("{} tests passed multiple times!!".format(len(testDuplicates)))
    print("Here are the duplicates and number of times passed: ")
    print(*sorted(testDuplicates), sep = "\n")
else:
    print("All tests that passed, passed only once ... OK")
print("==================================================")
print("===== FINISHED RUNNING check_tests.py =====")

sys.exit(errorMessage)
