all: clean format build

clean:
	@echo "Cleaning..."
	rm -rf build dist packet_helper_core.egg-info tests/.pytest_cache
	@echo "Cleaning... Done"

format:
	@echo "Formatting..."
	python -m black -t py38 .
	@echo "Formatting... Done"

build:
	@echo "Building..."
	python setup.py sdist bdist_wheel --universal
	@echo "Building... Done"

install-ptf: clean
	@echo "Getting ptf..."
	git clone https://github.com/PacketHelper/ptf.git
	cd ptf && python setup.py install
	python setup.py sdist bdist_wheel --universal
	pip install dist/ptf-0.9.1-py2.py3-none-any.whl
	rm -rf ptf
	@echo "Getting ptf... Done"