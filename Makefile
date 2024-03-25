EXTENSION = dpdecrypt        # extensions name
DATA = dpdecrypt--0.0.1.sql  # script
OBJS = dpdecrypt.o dpdecrypt.so

PGXS := $(shell pg_config --pgxs)
include $(PGXS)

copyso:
	cp dpdecrypt.so $(shell pg_config --pkglibdir)/dpdecrypt.so

# add the build target as the default target
all: copyso

