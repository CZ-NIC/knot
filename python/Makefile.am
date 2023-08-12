SUBDIRS = knot_exporter libknot
TARGETS = dist upload

.PHONY: $(TARGETS)
$(TARGETS):
	$(MAKE) -C knot_exporter $@
	$(MAKE) -C libknot $@
