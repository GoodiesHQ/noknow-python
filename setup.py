#!/usr/bin/env python3
from setuptools import setup, find_packages
from noknow import __version__ as noknow_version

setup(name="noknow",
      version=noknow_version,
      packages=find_packages(),
      install_requires=["ecpy"],
      description="Non-Interactive Zero-Knowledge Proof Implementation in Pure Python",
      long_description=open("README.md", "r", encoding="utf-8").read(),
      long_description_content_type="text/markdown",
      author="Austin Archer",
      author_email="aarcher73k@gmail.com",
      url="https://github.com/GoodiesHQ/noknow-python/",
      classifiers = [
            "License :: OSI Approved :: MIT License",
            "Topic :: Security :: Cryptography",
      ]
)

