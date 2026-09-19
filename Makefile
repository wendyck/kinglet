# kinglet

VENV := .venv
PY   := $(VENV)/bin/python
PROFILE ?= kinglet
REGION  ?= us-west-2
STACK   ?= kinglet

.PHONY: test lint build deploy clean

test:
	$(PY) -m pytest tests/unit -q

lint:
	$(PY) -m pyflakes src/ tests/

# config/repos.yml is the source of truth (SPEC.md §11) but the Lambdas need it
# inside the package, so it is copied in at build time rather than duplicated.
build:
	mkdir -p src/config src/schemas
	cp config/repos.yml src/config/repos.yml
	cp schemas/result.schema.json src/schemas/result.schema.json
	sam build

# Parameters come from samconfig.toml so a template default cannot drift away
# from what is actually deployed.
deploy: build
	sam deploy

clean:
	rm -rf .aws-sam src/config src/schemas
