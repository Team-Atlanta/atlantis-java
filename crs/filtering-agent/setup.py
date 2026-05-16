#!/usr/bin/env python3

from setuptools import find_packages, setup

setup(
    name="sink-picker",
    version="0.1.0",
    description="AI-powered sink point selection tool for vulnerability analysis",
    author="Cen Zhang, Fabian Fleischer",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "pick-sinks=sinkpicker.pick_sinks:main",
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "argparse",
    ],
)
