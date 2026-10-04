from setuptools import setup, find_packages

setup(
    name="soc-alert-toolkit",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "soc-alert=soc_alert.cli:main",
        ],
    },
    python_requires=">=3.8",
)





