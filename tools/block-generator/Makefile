debug-blockgen:
	python run_runner.py \
	--conduit-binary ./conduit \
	--scenario test_config.yml \
	--keep-alive \
	--skip-runner \
	--test-duration 30s

cleanup:
	python run_runner.py --purge

enter-pg:
	docker exec -it generator-test-container psql -U algorand -d generator_db
