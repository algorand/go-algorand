SCENARIO = scenarios/config.app.create.yml # test_config.yml
SKIP = --skip-runner
RESETDB = --reset-db
REPORTS = ../../tmp/RUN_RUNNER_OUTPUTS
DURATION = 30s

debug-blockgen:
	python run_runner.py \
	--conduit-binary ./conduit \
	--scenario $(SCENARIO) \
	--report-directory $(REPORTS) \
	--keep-alive $(SKIP) \
	--test-duration $(DURATION) \
	$(RESETDB)

clean-reports:
	rm -rf $(REPORTS) 

cleanup: clean-reports
	python run_runner.py --purge

enter-pg:
	docker exec -it generator-test-container psql -U algorand -d generator_db

run-runner:
	./block-generator runner --conduit-binary ./conduit \
	--log-level trace \
	--keep-data-dir \
	--test-duration $(DURATION) \
	--log-level trace \
	--postgres-connection-string "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable" \
	--scenario $(SCENARIO) \
	$(RESETDB) \
	--report-directory $(REPORTS)


