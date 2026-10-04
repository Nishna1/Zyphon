from setuptools import setup, find_packages

setup(
    name="zyphon",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "zyphon=zyphon.cli:main",
        ],
    },
    python_requires=">=3.8",
)




