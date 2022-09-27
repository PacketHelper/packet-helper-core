all: clean format build

.PHONY: check
check:
	black --check -t py310 .

clean:
	@echo "Cleaning..."
	rm -rf build dist packet_helper_core.egg-info tests/.pytest_cache
	@echo "Cleaning... Done"

format:
	@echo "Formatting..."
	python3 -m black -t py310 .
	@echo "Formatting... Done"

.PHONY: lint
lint:
	flake8 --max-line-length 99 --exclude __init__.py

build:
	@echo "Building..."
	python3 setup.py sdist bdist_wheel --universal
	@echo "Building... Done"
