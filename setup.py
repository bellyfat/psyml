#!/usr/bin/env python3
from setuptools import setup, find_packages


VERSION = "0.2.2"


with open("README.md") as fobj:
    long_description = fobj.read().strip()


if __name__ == "__main__":
    setup(
        name="psyml",
        version=VERSION,
        author="Kai Xia (夏恺)",
        author_email="kaix@fastmail.com",
        url="https://github.com/xiaket/psyml",
        description="Secrets manager using AWS Parameter Store",
        long_description=long_description,
        long_description_content_type="text/markdown",
        packages=find_packages(),
        py_modules=["psyml"],
        entry_points={"console_scripts": ["psyml = psyml.__main__:main"]},
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Topic :: Utilities",
        ],
    )
