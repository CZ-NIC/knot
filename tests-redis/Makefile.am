# Usage:
#  make test [OSS_REDIS_PATH=/path/to/redis-server] [NO_VALGRIND=1]
#  make clean

EXTRA_DIST = config.txt requirements.txt test.py

.PHONY: env clean-local

PYTHON = python3
VENV = .venv

# Create the virtualenv only if it doesn't already exist
$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -r requirements.txt

env: $(VENV)

test: env
	$(VENV)/bin/RLTest --randomize-ports --clear-logs --parallelism 4 \
	$(if $(OSS_REDIS_PATH),--oss-redis-path $(OSS_REDIS_PATH)) \
	$(if $(NO_VALGRIND),,--use-valgrind)

clean-local:
	rm -rf $(VENV) __pycache__ logs
