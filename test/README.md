# End to end tests

This directory contains the category of tests which we like to call "end to end". Primarily they consist of tests which first start a private network and then run a series of commands against that network.

These tests have grown since the project started and we have a number of different frameworks. There are a number of different tests, frameworks and tools in this directory.


# Directories
## Tests / Test Frameworks

* scripts - shell scripted integration test framework.
* e2e-go - tests that can be run with the `go test`.
* framework - functions and utilities used by the e2e-go tests.
* release-testing - a spot for specific release tests, see README files in subdirectories.
* muleCI - scripts run tests on a Jenkins server with mule
* packages - test that algod can be packaged on different docker environments.
* platform - test the algod amd64 package compatibility across different distributions.

## Tools / Data
* commandandcontrol - a remote control tool for algod. It allows you to manage many instances across many nodes.
* netperf-go - tools for semi-automated performance tests.
* testdata - datasets used by other tools not included in this repository.

# Scripts

Entry point to our integration test framework, including the e2e-go tests.

Must run from the root project directory, `./test/scripts/e2e.sh`

## scripts/e2e_client_runner.py and scripts/e2e_subs/

These tests are shell scripts which all run in parallel against a single private network.

Each script is provided with a wallet which contains a large supply of algos to use during the test.
```
usage: e2e_client_runner.py [-h] [--keep-temps] [--timeout TIMEOUT] [--verbose] [--version Future|vXX] [scripts [scripts ...]]

positional arguments:
  scripts            scripts to run

optional arguments:
  -h, --help             show this help message and exit
  --keep-temps           if set, keep all the test files
  --timeout TIMEOUT      integer seconds to wait for the scripts to run
  --verbose
  --version Future|vXX   selects the network template file
```

Tests in the `e2e_subs/serial` directory are executed serially instead of in parallel. This should only be used when absolutely necessary.

### Running a Single E2E Test

To run a specific test, run e2e.sh with -i interactive flag, and follow the instructions:
```bash
$ test/scripts/e2e.sh -i
```

In particular, after 30 seconds or so you'll be prompted with some Python virtual environment related exports. You should open a _new terminal shell_ at that point and do something like:

```bash
$ export VIRTUAL_ENV="/SOME/VERY/LONG/PATH/TO/ve"
$ export PATH="$VIRTUAL_ENV/bin:$PATH"
```

Once these virtual environment var's are in place, you can keep using that shell to run specific E2E tests with a commands such as:

```bash
python3 test/scripts/e2e_client_runner.py $(pwd)/test/scripts/e2e_subs/your_e2e_script.py
```

### Interaction through a Remote Debugger in a Python E2E Test Script

If you add the following code snippet to the top of your Python test script, you'll also be able to attach a remote debugger to the test:

```python
def initialize_debugger(port):
    import multiprocessing

    if multiprocessing.current_process().pid > 1:
        import debugpy

        debugpy.listen(("0.0.0.0", port))
        print("Debugger is ready to be attached, press F5", flush=True)
        debugpy.wait_for_client()
        print("Visual Studio Code debugger is now attached", flush=True)


# uncomment out the following to run a remote interactive debug session:
initialize_debugger(1339)
```

In this example, the debugger is listening on port 1339, but that's completely configurable. If you're using **VS Code**, you'll also want to modify your `launch.json` to look something like this:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Attach",
            "type": "python",
            "request": "attach",
            "localRoot": "${workspaceFolder}",
            "remoteRoot": "/FULL/PATH/TO/YOUR/go-algorand/",
            "port": 1339,
            "secret": "my_secret",
            "host": "localhost",
            "justMyCode": false
        }
    ]
}
```
For an example, have a look at [app-base64_decode.py](./scripts/e2e_subs/app-base64_decode.py).
