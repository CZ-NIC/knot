# Useful commands:
#  python3 -m venv .venv
#  source .venv/bin/activate
#  pip3 install -r requirements.txt
#  make test

EXTRA_DIST = config.txt requirements.txt test.py

.PHONY: test

test:
	RLTest --randomize-ports --clear-logs --parallelism 4
