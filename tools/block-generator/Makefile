SCENARIO = scenarios/config.allmixed.small.yml
SKIP = --skip-runner
RESETDB = --reset-db
REPORTS = ../../tmp/RUN_RUNNER_OUTPUTS
DURATION = 30s
VERBOSE = --verbose
CONDUIT = ./conduit
PGUSER = algorand
PGDB = generator_db
PGCONN = "host=localhost user=$(PGUSER) password=algorand dbname=$(PGDB) port=15432 sslmode=disable"

block-generator: clean-generator
	go build

clean-generator:
	rm -f block-generator

debug-blockgen:
	python scripts/run_runner.py \
	--conduit-binary $(CONDUIT) \
	--scenario $(SCENARIO) \
	--report-directory $(REPORTS) \
	--keep-alive $(SKIP) \
	--test-duration $(DURATION) \
	$(RESETDB)

enter-pg:
	docker exec -it generator-test-container psql -U $(PGUSER) -d $(PGDB)

clean-docker:
	docker rm -f generator-test-container

run-runner: block-generator
	./block-generator runner --conduit-binary $(CONDUIT) \
	--keep-data-dir \
	--test-duration $(DURATION) \
	--conduit-log-level trace \
	--postgres-connection-string $(PGCONN) \
	--scenario $(SCENARIO) \
	$(RESETDB) \
	$(VERBOSE) \
	--report-directory $(REPORTS)

clean-reports:
	rm -rf $(REPORTS)

pre-git-push:
	mv _go.mod go.mod
	mv _go.sum go.sum
	cd ../../ && make tidy

post-git-push:
	mv go.mod _go.mod
	mv go.sum _go.sum
	cd ../../ && make tidy && go get github.com/lib/pq
