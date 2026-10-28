.PHONY: check check-generated
check:
	$(MAKE) -C shared check
	$(MAKE) -C services/build check
	$(MAKE) -C services/deploy check

check-generated:
	$(MAKE) -C shared check-generated
