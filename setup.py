from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="adseceval",
    version="1.0.0",
    author="Ian Relecker",
    description="Active Directory Security Evaluation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ianrelecker/adsec",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "ldap3>=2.9.1",
        "cryptography>=38.0.0",
        "python-dateutil>=2.8.2",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "adseceval=adseceval.main:main",
        ],
    },
)