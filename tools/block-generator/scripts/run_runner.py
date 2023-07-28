import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time


POSTGRES_CONTAINER = "generator-test-container"
POSTGRES_PORT = 15432
POSTGRES_DATABASE = "generator_db"

REPORT_DIRECTORY = "../../tmp/OUTPUT_RUN_RUNNER_TEST"

CWD = Path.cwd()

NL = "\n"
BS = "\\"
DBS = BS * 2
Q = '"'
SQ = ' "'


def run_cmd(cmd):
    print(f"Running command: {cmd}")
    process = subprocess.Popen(
        shlex.split(cmd.replace("\\\n", " ")),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate()
    if (rcode := process.returncode) != 0:
        print(f"Error executing command: {cmd}")
        print(stderr.decode())
        sys.exit(rcode)
    return stdout.decode()


def up(args):
    run_cmd(f"docker rm -f {args.pg_container}")
    run_cmd(
        f"docker run -d --name {args.pg_container} -e POSTGRES_USER=algorand -e POSTGRES_PASSWORD=algorand -p {args.pg_port}:5432 postgres"
    )
    time.sleep(5)

    run_cmd(
        f'docker exec -it {args.pg_container} psql -Ualgorand -c "create database {args.pg_database}"'
    )


def down(args):
    run_cmd(f"docker rm -f {args.pg_container}")


def launch_json_args(cmd: str):
    def tighten(x):
        return x.replace(" \\", "\\")

    def wrap(x):
        return tighten(x) if x.startswith('"') else f'"{tighten(x)}"'

    newlines = []
    lines = cmd.splitlines()
    for i, line in enumerate(lines):
        if i == 0:
            continue
        if not line.startswith("--"):
            aline = wrap(line.replace(" ", ""))
        else:
            aline = ", ".join(map(wrap, line.split(" ", maxsplit=1)))

        if i < len(lines) - 1:
            aline += ","

        newlines.append(aline)
    return f"[{(NL.join(newlines)).replace(BS, '')}]"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--conduit-binary", help="Path to conduit binary")
    parser.add_argument(
        "--scenario",
        default=(default := CWD.parents[1] / "test_scenario.yml"),
        help=f"Scenario configuration file ({default=!s})",
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        default=False,
        help="Reset the DB and start at round 0 (default=False)",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        default=False,
        help="Shutdown container that has been kept alive (default=False)",
    )
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        default=False,
        help="Keep postgres container alive at end of run (default=False)",
    )
    parser.add_argument(
        "--pg-container",
        default=(default := POSTGRES_CONTAINER),
        help=f"Name of postgres container ({default=})",
    )
    parser.add_argument(
        "--pg-port",
        default=(default := POSTGRES_PORT),
        help=f"Postgres port ({default=})",
    )
    parser.add_argument(
        "--pg-database",
        default=(default := POSTGRES_DATABASE),
        help=f"Postgres database ({default=})",
    )
    parser.add_argument(
        "--report-directory",
        default=(default := REPORT_DIRECTORY),
        help=f"Report directory ({default=})",
    )
    parser.add_argument(
        "--build-generator",
        action="store_true",
        default=False,
        help="Build the generator binary (default=False)",
    )
    parser.add_argument(
        "--skip-runner",
        action="store_true",
        default=False,
        help="Skip running the generator (default=False)",
    )
    parser.add_argument(
        "--test-duration",
        default=(default := "30s"),
        help=f"Test duration ({default=})",
    )

    args = parser.parse_args()
    print(args)
    return args


def main():
    args = parse_args()

    try:
        if not args.purge:
            print(f"Using scenario file: {args.scenario}")
            print(f"!!! rm -rf {args.report_directory} !!!")
            run_cmd(f"rm -rf {args.report_directory}")

            if args.build_generator:
                print("Building generator.")
                os.chdir(CWD)
                run_cmd("go build")
                os.chdir("..")
            else:
                print("Skipping generator build.")

            print("Starting postgres container.")
            up(args)

            SLNL = "\\\n"
            generator_cmd = f"""{CWD}/block-generator \\
runner \\
--conduit-binary "{args.conduit_binary}" \\
--report-directory {args.report_directory} \\
--test-duration {args.test_duration} \\
--conduit-log-level trace \\
--postgres-connection-string "host=localhost user=algorand password=algorand dbname={args.pg_database} port={args.pg_port} sslmode=disable" \\
--scenario {args.scenario} {DBS + NL + '--reset-db' if args.reset_db else ''}"""
            if args.skip_runner:
                print("Skipping test runner.")
                print(f"Run it yourself:\n{generator_cmd}")
                print(
                    f"""`launch.json` args:
{launch_json_args(generator_cmd)}"""
                )
            else:
                print("Starting test runner")
                run_cmd(generator_cmd)
        else:
            print("Purging postgres container - NO OTHER ACTION TAKEN")
            down(args)
    finally:
        if not args.keep_alive:
            print("Stopping postgres container.")
            down(args)
        else:
            print(f"Keeping postgres container alive: {args.pg_container}")
            print(f"Also, not removing report directory: {args.report_directory}")


if __name__ == "__main__":
    main()
