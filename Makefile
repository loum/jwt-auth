PY=/usr/bin/env python
PYTHONPATH=.
DJANGO_TEST=./manage.py test
GIT=/usr/bin/git
DJANGO_TEST_VERBOSITY=2
DJANGO_SETTINGS_MODULE=auth.settings
TEST=auth.tests

test:
	LOG_HANDLER=console PYTHONPATH=$(PYTHONPATH) \
	$(DJANGO_TEST) --nocapture --verbosity=$(DJANGO_TEST_VERBOSITY) $(TEST)

docs:
	PYTHONPATH=$(PYTHONPATH) \
	DJANGO_SETTINGS_MODULE=$(DJANGO_SETTINGS_MODULE) \
	sphinx-build -b html doc/source doc/build

clean:
	$(GIT) clean -xdf

# .PHONY: test docs
