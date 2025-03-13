"""Setup script for TenetSec."""

from setuptools import setup, find_packages

setup(
    name="tenetsec",
    version="0.1.0",
    description="Microsoft 365 Security Assessment Tool",
    author="TenetSec",
    author_email="info@tenetsec.example.com",
    packages=find_packages(),
    install_requires=[
        "msal>=1.20.0",
        "requests>=2.28.1",
        "pandas>=1.5.0",
        "matplotlib>=3.6.0",
        "seaborn>=0.12.0",
        "python-dotenv>=0.21.0",
        "rich>=12.6.0",
        "PyYAML>=6.0"
    ],
    entry_points={
        "console_scripts": [
            "tenetsec=tenetsec.main:main",
        ],
    },
    python_requires=">=3.8",
)