all: clean format build

.PHONY: check
check:
	black --check -t py311 .

.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf build dist packet_helper_core.egg-info tests/.pytest_cache
	@echo "Cleaning... Done"

.PHONY: format
format:
	@echo "Formatting..."
	python3 -m black -t py311 .
	@echo "Formatting... Done"

.PHONY: lint
lint:
	flake8 --max-line-length 99 --exclude __init__.py

.PHONY: build
build:
	@echo "Building..."
	python3 setup.py sdist bdist_wheel --universal
	@echo "Building... Done"

.PHONY: test
test:
	mkdir -p static && touch static/index.html
	PYTHONPATH=${PWD} pytest tests/integration
