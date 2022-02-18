all: clean format build

clean:
	@echo "Cleaning..."
	rm -rf build dist packet_helper_core.egg-info tests/.pytest_cache
	@echo "Cleaning... Done"

format:
	@echo "Formatting..."
	python3 -m black -t py38 .
	@echo "Formatting... Done"

build:
	@echo "Building..."
	python3 setup.py sdist bdist_wheel --universal
	@echo "Building... Done"
