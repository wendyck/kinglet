# kinglet

VENV := .venv
PY   := $(VENV)/bin/python
PROFILE ?= kinglet
REGION  ?= us-west-2
STACK   ?= kinglet

.PHONY: test lint build deploy image clean

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

# The reviewer image shares safe_tar with the Lambdas. Docker cannot reach
# outside its build context, so it is copied in rather than duplicated.
image:
	mkdir -p reviewer/vendor
	cp src/common/safe_tar.py reviewer/vendor/safe_tar.py
	docker build --platform=linux/arm64 -t kinglet-reviewer:dev reviewer/

clean:
	rm -rf .aws-sam src/config src/schemas reviewer/vendor
