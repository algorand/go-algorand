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

There are three (optional) environment variables that can be used to control the behavior of the tests:

- TESTDATADIR
    - The location of the `genesis.json` file.
    - Defaults to `$GOPATH/src/github.com/algorand/go-algorand/test/testdata`.

- TESTDIR
    - This is the location to where test artifacts will be written.
    - Defaults to a location in the `/tmp` directory tree that is created at runtime.

- TESTFILTER
    - Allows for fine-grained control over which tests are selected to be run.
    - The filter is a regular expression.
        - For example, if you had hundreds of tests and only wanted to test `barTest.exp` and `carTest.exp`, you'd
          set the filter to be `export TESTFILTER=[b,c]ar`.
    - Defaults to all tests (`.*`).

NOTE: the file name should have the suffix: "Test.exp"

To run the Goal Expect test, run the following command from the top level go-algorand directory:

```
go test -v test/e2e-go/cli/goal/expect/goal_expect_test.go
```

Here is an example of running the tests with a preset `TESTDIR` and `TESTFILTER`:

```
# This will target all tests such as `foobar1Test.exp`, `foobar2Test.exp`, etc. but not `foobar10Test.exp`.
export TESTFILTER=foobar[0-9]Test
export TESTDIR=baz

go test -v test/e2e-go/cli/goal/expect/goal_expect_test.go

# OR

TESTFILTER=foobar[0-9]Test TESTDIR=baz go test -v test/e2e-go/cli/goal/expect/goal_expect_test.go
```

> Of course, a test can always be run directly by `expect`, i.e. `expect rekeyTest.exp $TESTDIR $TESTDATADIR`.

## Adding New Tests

To add a test, create a copy of the `test/e2e-go/cli/goal/expect/basicGoalTest.exp` file within the same directory.
Give it a name that reflects the purpose of the test, and make sure the file name suffix matches `'Test.exp'`.  This will allow it to be included when running the expect tests.

## Common Procedures

Reusable and commonly used goal commands can be defined as procedures. This helps reduce code bulk and errors in the expect tests.  See the file `goalExpectCommon.exp` for the list of available procedures.

