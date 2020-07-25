# Goal Testing with Expect

Expect is a framework for testing command line interfaces (CLI).  It is a extension to the TCL shell designed to automate invoking, interacting with, and validating results of CLIs. 
 
We use expect to test the Algorand Goal CLI.

## Setup 

From the go-algorand root directory, setup the environment and build the binaries as described in the top-level project README.md file.  

#### Initialize the project
```bash
git clone https://github.com/algorand/go-algorand
cd go-algorand
./scripts/configure_dev.sh
```
#### Build the binaries
```bash
make clean install
```

#### Running the integration tests

Running the integration tests will invoke the expect tests.  Execute the following command to run the integration tests.

```bash
make integration
```

#### Set environment variables

The `GOPATH` should be set to your local Go projects directory. 
The `PATH` environment variable should include `$GOPATH/bin`. For example:

```bash
export GOPATH=~/path/to/goprojects
export PATH=$(go env GOPATH | cut -d':' -f1 ):${PATH}
```


## Running the Expect Tests

To run the Goal Expect test, run the following command from the top level go-algorand directory:

`go test -v test/e2e-go/cli/goal/expect/goal_expect_test.go` 


## Adding New Tests

To add a test, create a copy of the `test/e2e-go/cli/goal/expect/basicGoalTest.exp` file within the same directory. 
Give it a name that reflects the purpose of the test, and make sure the the file name suffix matches `'Test.exp'`.  This will allow it to be included when running the expect tests.
 
## Common Procedures

Reusable and commonly used goal commands can be defined as procedures. This helps reduce code bulk and errors in the expect tests.  See the file `goalExpectCommon.exp` for the list of available procedures.  
