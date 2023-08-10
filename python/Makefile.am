EXTRA_DIST =			\
	libknot/__init__.py.in	\
	libknot/control.py	\
	libknot/dname.py	\
	libknot/probe.py	\
	pyproject.toml.in	\
	setup.py.in		\
	README.md

clean-local:
	-rm -rf dist *.egg-info

dist: clean-local
	@if hatchling -h &> /dev/null; then \
	  hatchling build; \
	else \
	  python3 setup.py sdist; \
	fi

upload:
	twine upload dist/*
