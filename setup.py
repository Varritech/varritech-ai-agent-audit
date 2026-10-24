from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).resolve().parent
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="varritech-ai-agent-audit",
    version="0.1.0",
    description="Audit the AI coding agents running on your machine — before they leak your repo.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Varritech",
    author_email="christian@varritech.com",
    license="MIT",
    url="https://github.com/Varritech/varritech-ai-agent-audit",
    packages=find_packages(exclude=["tests", "tests.*"]),
    py_modules=["cli"],
    package_data={
        "scanner": ["agents.yaml", "secrets.yaml"],
    },
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "psutil>=5.9",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "vaia=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development",
    ],
)