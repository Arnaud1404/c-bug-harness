# Rootless podman maps uids itself; --user would leave files it cannot own.
CONTAINER ?= docker
ANALYZERS_IMAGE = c-bug-harness-analyzers
ifeq ($(CONTAINER),podman)
    RUN_AS = --userns=keep-id
else
    RUN_AS = --user $(shell id -u):$(shell id -g)
endif

.PHONY: test lint analyzers-image docker-analyzers

test:
	python -m pytest -q

lint:
	ruff check .
	shellcheck analyzers/*.sh agent-eval/*.sh agent-eval/tools/*.sh scripts/*.sh

analyzers-image:
	$(CONTAINER) build -f analyzers/Dockerfile -t $(ANALYZERS_IMAGE) .

docker-analyzers: analyzers-image
	$(CONTAINER) run --rm $(RUN_AS) -v "$(CURDIR):/src" $(ANALYZERS_IMAGE) ./analyzers/test.sh
