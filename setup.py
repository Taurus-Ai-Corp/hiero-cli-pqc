from setuptools import setup, find_namespace_packages

setup(
    name="gridera-scan-cli",
    version="0.1.0",
    description="Post-Quantum Cryptography audit CLI for the GRIDERA platform",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="TAURUS AI Corp",
    author_email="admin@taurusai.io",
    url="https://github.com/Taurus-Ai-Corp/gridera-scan-cli",
    license="MIT",
    packages=find_namespace_packages(include=["cli_anything.*"]),
    install_requires=[
        "click>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "gridera-scan=cli_anything.hiero_pqc.hiero_pqc_cli:cli",
            "gridera-scan-cli=cli_anything.hiero_pqc.hiero_pqc_cli:cli",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
    ],
    keywords="gridera pqc post-quantum cryptography hedera hiero ssl tls audit compliance nist",
)
