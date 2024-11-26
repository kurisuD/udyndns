"""
udyndns setup files
"""
# coding=utf-8
import setuptools

from udyndns.version import __version__

with open("README.md", encoding='utf8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="udyndns",
    version=__version__,
    author="KurisuD",
    author_email="KurisuD@pypi.darnand.net",
    description="A very simple OVH dyndns client to workaround difficulties with Ubiquity unadyn...",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KurisuD/udyndns",
    packages=setuptools.find_packages(),
    install_requires=['aiounifi >= 80', 'pap_logger'],
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "License :: Public Domain",
        "Operating System :: POSIX :: Linux",
        "Topic :: Home Automation",
        "Topic :: Internet :: Name Service (DNS)"
    ],
)
