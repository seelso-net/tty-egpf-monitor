#!/usr/bin/env python3
"""
Setup script for tty-egpf-monitor Python client.

This is a fallback setup.py for older pip versions.
Modern installations should use pyproject.toml.
"""

from setuptools import setup, find_packages

# Read version from __init__.py
def get_version():
    with open("tty_egpf_monitor/__init__.py") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split('"')[1]
    return "0.0.0"

# Read long description from README
def get_long_description():
    try:
        with open("README.md", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Python client library for TTY eBPF Monitor daemon"

setup(
    name="tty-egpf-monitor",
    version=get_version(),
    description="Python client library for TTY eBPF Monitor daemon",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="TTY eBPF Monitor Team",
    author_email="contact@seelso.net",
    url="https://github.com/seelso-net/tty-egpf-monitor",
    project_urls={
        "Homepage": "https://github.com/seelso-net/tty-egpf-monitor",
        "Documentation": "https://github.com/seelso-net/tty-egpf-monitor/blob/main/README.md",
        "Repository": "https://github.com/seelso-net/tty-egpf-monitor",
        "Bug Tracker": "https://github.com/seelso-net/tty-egpf-monitor/issues",
        "APT Repository": "https://seelso-net.github.io/tty-egpf-monitor",
    },
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov", 
            "black",
            "flake8",
            "mypy",
            "build",
            "twine"
        ]
    },
    entry_points={
        "console_scripts": [
            "tty-egpf-monitor-py=tty_egpf_monitor.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console", 
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Hardware :: Hardware Drivers",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Terminals :: Serial",
    ],
    keywords="serial tty monitoring ebpf uart debugging reverse-engineering protocol-analysis hardware",
    include_package_data=True,
    zip_safe=False,
)
