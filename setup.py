from setuptools import setup, find_packages

setup(
    name="cnsl-guard",
    version="1.0.0",
    author="Rahad Bhuiya",
    description="Cyber Network Security Layer — real-time SSH brute-force detection and auto-blocking",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/cnsl",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "full":    ["aiohttp>=3.9", "aiosqlite>=0.19", "pyyaml>=6.0"],
        "notify":  ["aiohttp>=3.9"],
        "db":      ["aiosqlite>=0.19"],
        "yaml":    ["pyyaml>=6.0"],
        "dev":     ["pytest>=7", "pytest-asyncio", "aiohttp>=3.9", "aiosqlite>=0.19", "pyyaml>=6.0"],
    },
    entry_points={
        "console_scripts": ["cnsl=cnsl.engine:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Intended Audience :: System Administrators",
    ],
    keywords="security ssh brute-force iptables ipset intrusion detection",
)