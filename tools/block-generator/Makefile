SCENARIO = scenarios/config.app.create.yml # test_config.yml
SKIP = --skip-runner
RESETDB = # --reset-db
REPORTS = RUN_RUNNER_OUTPUTS

debug-blockgen:
	python run_runner.py \
	--conduit-binary ./conduit \
	--scenario $(SCENARIO) \
	--report-directory $(REPORTS) \
	--keep-alive $(SKIP) \
	--test-duration 30s \
	$(RESETDB)

clean-reports:
	rm -rf reports 

cleanup: clean-reports
	python run_runner.py --purge

enter-pg:
	docker exec -it generator-test-container psql -U algorand -d generator_db

run-runner:
	./block-generator runner --conduit-binary ./conduit \
	--log-level trace \
	--keep-data-dir \
	--report-directory $(REPORTS) \
	--test-duration 30s --log-level trace \
	--postgres-connection-string "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable" \
	--scenario $(SCENARIO) \
	$(RESETDB)
