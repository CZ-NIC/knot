EXTRA_DIST =			\
	libknot/__init__.py.in	\
	libknot/control.py	\
	libknot/dname.py	\
	libknot/probe.py	\
	pyproject.toml.in	\
	README.md

clean-local:
	-rm -rf dist *.egg-info

dist: clean-local
	hatchling build

upload:
	twine upload dist/*
