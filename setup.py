import setuptools
from ptwebdiscover._version import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ptwebdiscover",
    description="Web Source Discovery Tool",
    url="https://www.penterep.com/",
    author="Penterep",
    author_email="info@penterep.com",
    version=__version__,
    license="GPLv3+",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"
    ],
    python_requires = '>=3.6',
    install_requires=["ptlibs>=1.0.3,<2", "requests", "appdirs", "tldextract>=5.0.0", "treelib"],
    entry_points = {'console_scripts': ['ptwebdiscover = ptwebdiscover.ptwebdiscover:main']},
    include_package_data= True,
    long_description=long_description,
    long_description_content_type="text/markdown",
)