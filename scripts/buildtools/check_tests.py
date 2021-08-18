import json
import sys

if len(sys.argv) != 2:
    print("Wrong number of arguments passed. Please pass one argument: json format test results file path (e.g. /tmp/results/testresults.json)")
    sys.exit(1)
filepath = sys.argv[1]

testList = []
# testListRan = []
testListPassed = []
# testListSkipped = []
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
        # elif testDict["Action"] == 'run':
            # testListRan.append(fullTestName)
        # elif testDict["Action"] == 'skip':
            # testListSkipped.append(fullTestName)

f.close()

# Dedup:
testListDeduped = list(set(testList))
# testListRanDeduped = list(set(testListRan))
# testListSkippedDeduped = list(set(testListSkipped))
testListPassedDeduped = list(set(testListPassed))
countTotalDeduped = len(testListDeduped)
countPassed = len(testListPassed)
countPassedDeduped = len(testListPassedDeduped)

print("Saw " + str(countTotalDeduped) + " tests total")
# print(str(len(testListRanDeduped)) + " ran")
# print(str(len(testListSkippedDeduped)) + " skipped")
print(str(countPassed) + " passed before dedup")
print(str(countPassedDeduped) + " passed after dedup")
errorCode = ''
if countTotalDeduped != countPassedDeduped:
    countNotPassed = countTotalDeduped - countPassedDeduped
    print(str(countNotPassed) + " tests didn't pass!!")
    notPassed = set(testListDeduped) - set(testListPassedDeduped)
    print("Here are the ones that didn't pass even once: ")
    print(*sorted(notPassed), sep = "\n")
    errorCode += "FAIL ERROR: " + str(countNotPassed) + " tests didn't pass!!\n"
else:
    print("Seems all tests passed at least once ... OK")

if countPassed != countPassedDeduped:
    testDuplicates = set([testName + " " + str(testListPassed.count(testName)) for testName in testListPassed if testListPassed.count(testName) > 1])
    print(str(len(testDuplicates)) + " tests passed multiple times!! ... FAIL ERROR")
    print("Here are the duplicates: ")
    # print(*sorted(testDuplicates), sep = "\n")
    errorCode += "FAIL ERROR: " + str(len(testDuplicates)) + " tests passed multiple times!!\n"
else:
    print("Seems all tests that passed, passed only once ... OK")

sys.exit(errorCode)
