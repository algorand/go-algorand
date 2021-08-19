import json
import sys

print("===== STARTED RUNNING check_tests.py =====")
if len(sys.argv) != 2:
    print("Wrong number of arguments passed. Please pass one argument: json format test results file path (e.g. /tmp/results/testresults.json)")
    sys.exit(1)
filepath = sys.argv[1]

# Go through the given file one json object at a time, and record into lists
testList = []
testListPassed = []
with open(filepath) as f:
    for jsonObj in f:
        testDict = json.loads(jsonObj)
        if 'Test' not in testDict:
            continue
        
        fullTestName = testDict['Package'] + ' ' + testDict['Test']
        testList.append(fullTestName)
        # actions can be: output, run, skip, pass
        if 'pass' in testDict["Action"]:
            testListPassed.append(fullTestName)

f.close()

# Dedup some lists:
testListDeduped = list(set(testList))
testListPassedDeduped = list(set(testListPassed))
countTotalDeduped = len(testListDeduped)
countPassed = len(testListPassed)
countPassedDeduped = len(testListPassedDeduped)

# Summary
print("==================================================")
print("Saw " + str(countTotalDeduped) + " tests total")
print(str(countPassed) + " passed before dedup")
print(str(countPassedDeduped) + " passed after dedup")
print("==================================================")

# Check if all seen tests have passed
errorCode = ''
if countTotalDeduped != countPassedDeduped:
    countNotPassed = countTotalDeduped - countPassedDeduped
    print(str(countNotPassed) + " tests didn't pass!!")
    notPassed = set(testListDeduped) - set(testListPassedDeduped)
    print("Here are the ones that didn't pass even once: ")
    print(*sorted(notPassed), sep = "\n")
    errorCode += "FAIL ERROR: " + str(countNotPassed) + " tests didn't pass!!\n"
else:
    print("All tests passed at least once ... OK")

# Check for duplicates in the passed tests
print("==================================================")
if countPassed != countPassedDeduped:
    testDuplicates = set([testName + " " + str(testListPassed.count(testName)) for testName in testListPassed if testListPassed.count(testName) > 1])
    print(str(len(testDuplicates)) + " tests passed multiple times!! ... FAIL ERROR")
    print("Here are the duplicates: ")
    print(*sorted(testDuplicates), sep = "\n")
    errorCode += "FAIL ERROR: " + str(len(testDuplicates)) + " tests passed multiple times!!\n"
else:
    print("All tests that passed, passed only once ... OK")
print("==================================================")
print("===== FINISHED RUNNING check_tests.py =====")

sys.exit(errorCode)
