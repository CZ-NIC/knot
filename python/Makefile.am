EXTRA_DIST = \
	setup.py.in

nobase_python_PYTHON = \
	libknot/__init__.py	\
	libknot/control.py

clean-local:
	-rm -rf dist *.egg-info

dist: clean-local
	python3 setup.py sdist

upload:
	twine upload dist/*
