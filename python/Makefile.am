EXTRA_DIST =			\
	libknot/__init__.py.in	\
	libknot/control.py	\
	setup.py.in		\
	stats_http.py		\
	stats_influxdb.py
	
clean-local:
	-rm -rf dist *.egg-info

dist: clean-local
	python3 setup.py sdist

upload:
	twine upload dist/*
