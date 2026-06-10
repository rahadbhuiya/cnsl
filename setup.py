from setuptools import setup, find_packages

setup(
    name="cnsl",
    version="2.0.0",
    author="Rahad Bhuiya",
    description="Correlated Network Security Layer — A self-hosted SIEM for Linux",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/rahadbhuiya/cnsl",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        #  individual feature extras 
        "notify":   ["aiohttp>=3.9"],
        "db":       ["aiosqlite>=0.19"],
        "yaml":     ["pyyaml>=6.0"],
        "auth":     ["bcrypt>=4.0", "PyJWT>=2.8"],
        "2fa":      ["pyotp>=2.9"],
        "geoip":    ["geoip2>=4.7"],
        "ml":       ["scikit-learn>=1.4", "numpy>=1.26"],
        "reports":  ["reportlab>=4.0"],
        "redis":    ["redis>=5.0"],
        "kafka":    ["aiokafka>=0.10"],
        #  batteries-included 
        "full": [
            "aiohttp>=3.9",
            "aiosqlite>=0.19",
            "pyyaml>=6.0",
            "bcrypt>=4.0",
            "PyJWT>=2.8",
            "pyotp>=2.9",
            "scikit-learn>=1.4",
            "numpy>=1.26",
            "reportlab>=4.0",
        ],
        #  development 
        "dev": [
            "pytest>=7",
            "pytest-asyncio",
            "pytest-timeout",
            "aiohttp>=3.9",
            "aiosqlite>=0.19",
            "pyyaml>=6.0",
            "bcrypt>=4.0",
            "PyJWT>=2.8",
            "pyotp>=2.9",
            "scikit-learn>=1.4",
            "numpy>=1.26",
            "reportlab>=4.0",
        ],
    },
    entry_points={
        "console_scripts": ["cnsl=cnsl.engine:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Intended Audience :: System Administrators",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=(
        "security siem ssh brute-force iptables ipset intrusion-detection "
        "threat-detection linux honeypot ml anomaly-detection"
    ),
)