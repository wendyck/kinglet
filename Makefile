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
	mkdir -p src/config
	cp config/repos.yml src/config/repos.yml
	sam build --use-container --parameter-overrides ScheduleState=DISABLED

deploy: build
	sam deploy --profile $(PROFILE) --region $(REGION) --stack-name $(STACK) \
	  --capabilities CAPABILITY_IAM --resolve-s3 --no-confirm-changeset

clean:
	rm -rf .aws-sam src/config
