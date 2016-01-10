PY=$(shell which python3)
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

VENV_DIR_EXISTS=$(shell [ -e "venv" ] && echo 1 || echo 0)
init:
ifeq ($(VENV_DIR_EXISTS), 1)
	$(info ### Deleting existing environment venv )
	$(shell which rm) -fr venv
endif
	$(info ### Creating virtual environment venv ...)
	virtualenv -p $(PY) --no-site-packages venv
	venv/bin/pip install --upgrade pip==1.5.6
	venv/bin/pip install --upgrade setuptools==0.9.8
	venv/bin/pip install -e .

init_rh:
ifeq ($(VENV_DIR_EXISTS), 1)
	$(info ### Deleting existing environment venv )
	$(shell which rm) -fr venv
endif
	$(info ### Creating virtual environment venv ...)
	python3.4 -m venv --without-pip venv
	# wget https://pypi.python.org/packages/source/s/setuptools/setuptools-3.4.4.tar.gz
	tar -vzxf setuptools-3.4.4.tar.gz
	cd setuptools-3.4.4 && ../venv/bin/python setup.py install
	wget https://pypi.python.org/packages/source/p/pip/pip-1.5.6.tar.gz
	tar -vzxf pip-1.5.6.tar.gz
	cd pip-1.5.6 && ../venv/bin/python setup.py install
	venv/bin/pip install -e .

.PHONY: test docs
