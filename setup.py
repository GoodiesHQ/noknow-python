#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(name="noknow",
      version="0.1",
      packages=find_packages(),
      install_requires=["gmpy2", "ecpy"],
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

