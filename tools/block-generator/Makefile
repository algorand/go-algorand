# The following variables are primarily useful for tuning dev testing and
# appear in the targets pg-up, pg-enter, pg-down, pg-query, 
# run-runner, run-file-exporter, and benchmark-blocks-export:
SCENARIO = scenarios/benchmarks/stress.50000.yml
RESETDB = --reset-db
TIMES = 1
REPORTS = ../../tmp/RUN_RUNNER_OUTPUTS
DURATION = 30s
VERBOSE = --verbose
CONDUIT = ./conduit
TEMPLATE = # --template file-exporter (default postgres-exporter)
PGUSER = algorand
PGDB = generator_db
PGCONT = "generator-test-container"
PGCONN = "host=localhost user=$(PGUSER) password=algorand dbname=$(PGDB) port=15432 sslmode=disable"
PGRUNNER = --postgres-connection-string $(PGCONN)

block-generator: clean-generator
	go build

clean-generator:
	rm -f block-generator

pg-up:
	docker run --name $(PGCONT) -p 15432:5432 -e POSTGRES_USER=$(PGUSER) -e POSTGRES_PASSWORD=algorand -e POSTGRES_DB=$(PGDB) -d postgres

pg-enter:
	docker exec -it $(PGCONT) psql -U $(PGUSER) -d $(PGDB)

QUERY := -c "select count(*) from txn;"
pg-query:
	psql $(PGCONN) $(QUERY)

pg-down:
	docker rm -f $(PGCONT)

run-runner: block-generator
	./block-generator runner --conduit-binary $(CONDUIT) \
	--keep-data-dir \
	--test-duration $(DURATION) \
	--conduit-log-level trace \
	$(TEMPLATE) \
	$(PGRUNNER) \
	--scenario $(SCENARIO) \
	$(RESETDB) \
	$(VERBOSE) \
	--report-directory $(REPORTS)
	--times $(TIMES)

run-file-exporter:
	make run-runner TEMPLATE="--template file-exporter" TIMES=1 RESETDB= PGRUNNER=

BENCHMARK = "organic.25000"
benchmark-blocks-export: block-generator
	make run-file-exporter DURATION=60s SCENARIO=scenarios/benchmarks/$(BENCHMARK).yml REPORTS=$(BENCHMARK)

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
