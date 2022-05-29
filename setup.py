from distutils.core import setup
from setuptools import find_packages
import sys

if sys.version_info < (3,):
    print("Please use python3.")
    sys.exit(1)


requires = [
    "pyjwt",
    "requests",
    "zope.interface",
]

sqlalchemy_deps = ["sqlalchemy"]

pyramid_deps = ["pyramid"]


setup(
    name="shopauth",
    version="0.1a",
    description="Unofficial auth library for shopify apps.",
    author="Ian Wilson",
    author_email="ian@laspilitas.com",
    url="https://www.github.com/ianjosephwilson/shopauth",
    install_requires=requires,
    packages=find_packages(),
    package_dir={"shopauth": "shopauth"},
    include_package_data=True,
    zip_safe=False,
    extras_require={
        "sqlalchemy": sqlalchemy_deps,
        "pyramid": pyramid_deps,
        "dev": ["flake8", "black"],
    },
)
