# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository checkout as the build context, then runs its security audit inside
# the resulting image with no network access, so every module and tool that tests need is fetched here.
# Keep the Go version in sync with scripts/get_golang_version.sh.
FROM golang:1.27.3-bookworm

# GOTOOLCHAIN=local stops go.mod's toolchain line from triggering a download once offline.
# ALGOTEST and KMD_NOUSB match the environment CI runs tests in (.github/workflows/ci-pr.yml). CI's
# ALGORAND_DEADLOCK=enable is left out so the installed binaries keep the release default (deadlock detection off);
# unit tests run with go-deadlock enabled regardless.
ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local \
    ALGOTEST=1 \
    KMD_NOUSB=True

# Same packages as scripts/install_linux_deps.sh: autotools build our libsodium fork; expect, jq and sqlite3 are
# used by the e2e tests.
RUN apt-get update && apt-get install -y --no-install-recommends \
      autoconf automake bsdmainutils build-essential ca-certificates expect git jq libtool \
      procps python3 sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

RUN go mod download \
    && go mod download -modfile=tool.mod \
    && go build -modfile=tool.mod -o /dev/null gotest.tools/gotestsum golang.org/x/tools/cmd/stringer \
    && for d in tools/block-generator tools/x-repo-types tools/debug/algodump; do (cd "$d" && go mod download); done

# Builds libsodium, then algod, goal, kmd, algokey and the other binaries into /go/bin.
RUN make build

# Compile every test binary (without running tests) so the offline build cache already holds them, then run the
# short tests of the consensus-critical packages as a smoke check. Failures are reported but do not fail the image.
ENV GOFLAGS="-tags=sqlite_unlock_notify,sqlite_omit_load_extension"
RUN go test -count=1 -run '^$' ./... >/dev/null \
    || echo "WARNING: some test packages failed to compile"
RUN go test -short -timeout 20m \
      ./crypto/... ./data/transactions/... ./data/basics/... ./protocol/... ./agreement/ \
    || echo "WARNING: short tests reported failures"

# Go e2e tests (test/e2e-go) start local private networks from these binaries; see AGENTS.md for how to run them.
ENV NODEBINDIR=/go/bin \
    TESTDATADIR=/src/test/testdata \
    TESTDIR=/tmp

# Reproducers and patches written during the audit must also build with the network disabled.
ENV GOPROXY=off \
    GOSUMDB=off

CMD ["bash"]
