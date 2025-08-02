"""Setup script for pyCheckwatt module."""

from setuptools import find_packages, setup

MIN_PY_VERSION = "3.10"
PACKAGES = find_packages()
VERSION = "0.2.9"

setup(
    name="pycheckwatt",
    packages=PACKAGES,
    version=VERSION,
    description="A python library for communicating with CheckWatt EnergyInBalance",
    author="Marcus Karlsson",
    author_email="macke.karlsson@gmail.com",
    license="MIT",
    url="https://github.com/faanskit/pycheckwatt",
    download_url=f"https://github.com/faanskit/pycheckwatt/archive/v{VERSION}.tar.gz",
    install_requires=["aiohttp", "pydantic", "relativedelta"],
    keywords=["checkwatt", "energyinbalance", "homeassistant"],
    python_requires=f">={MIN_PY_VERSION}",
)
