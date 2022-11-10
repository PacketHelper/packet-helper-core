[![Run tests](https://github.com/PacketHelper/packet-helper-core/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/PacketHelper/packet-helper-core/actions/workflows/pytest.yml)
[![Verify code](https://github.com/PacketHelper/packet-helper-core/actions/workflows/verify_code.yml/badge.svg)](https://github.com/PacketHelper/packet-helper-core/actions/workflows/verify_code.yml)

# packet-helper-core
Core application to parse packets. 

## Requirements
To run the packet-helper-core on the machine, some dependencies need to be installed. 
Recommended OS is *Ubuntu 18.04*.

```text
# to skip interactive mode, export 
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get -y install wireshark
sudo apt-get install -y --allow-change-held-packages --force-yes tshark
```

Recommended *Python 3.11* (as minimal). 

To verify that all works, try to run test using `pytest` (in root directory of this package):

```text
pip install -r requirements.txt

pytest 
```