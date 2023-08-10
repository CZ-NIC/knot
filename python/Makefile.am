EXTRA_DIST =			\
	libknot/__init__.py.in	\
	libknot/control.py	\
	libknot/dname.py	\
	libknot/probe.py	\
	libknot.toml.in		\
	README.md

clean-local:
	-rm -rf dist *.egg-info

dist: clean-local
	python3 -m build

upload:
	twine upload dist/*
