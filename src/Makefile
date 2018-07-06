MODULES = hss xmssmt
all:
	for dir in $(MODULES); do \
		(cd $$dir; ${MAKE} all); \
	done

clean:
	for dir in $(MODULES); do \
		(cd $$dir; ${MAKE} clean); \
	done
