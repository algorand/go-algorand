SCENARIO = test_config.yml
SKIP = --skip-runner
RESETDB = --reset-db
debug-blockgen:
	python run_runner.py \
	--conduit-binary ./conduit \
	--scenario $(SCENARIO) \
	--keep-alive $(SKIP) \
	--test-duration 30s \
	$(RESETDB)

cleanup:
	python run_runner.py --purge

enter-pg:
	docker exec -it generator-test-container psql -U algorand -d generator_db
