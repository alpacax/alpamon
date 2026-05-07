TIME      ?= $(shell command -v gtime 2>/dev/null || command -v /usr/bin/time)
TIME_FLAG ?= $(shell [ "$$(uname)" = "Darwin" ] && echo -l || echo -v)

.PHONY: bench-mem
bench-mem:
	go test -c -o /tmp/file_bench ./pkg/executor/handlers/file/
	@for sz in 1MB 10MB 100MB; do \
		echo "==== upload $$sz ===="; \
		$(TIME) $(TIME_FLAG) /tmp/file_bench -test.run=^$$ -test.bench=BenchmarkUpload_E2E_Local/$$sz -test.benchmem -test.benchtime=1x 2>&1 | tail -25; \
	done
