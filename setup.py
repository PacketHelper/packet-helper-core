import os

from setuptools import setup, find_packages

with open("./README.md", "r") as fh:
    long_description = fh.read()

requirements_txt = os.path.join(os.path.dirname(__file__), "requirements.txt")

with open(requirements_txt, "r", encoding="utf-8") as fin:
    requires = [
        line.strip()
        for line in fin
        if line and line.strip() and not line.strip().startswith("#")
    ]

setup(
    name="packet_helper_core",
    description="Engine to decode raw string hex into packets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Nex Sabre",
    author_email="nexsabre@protonmail.com",
    version="0.1",
    url="https://github.com/PacketHelper/packet-helper-core",
    packages=find_packages(exclude=("tests",)),
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    license="GPLv2",
    install_requires=requires,
)
