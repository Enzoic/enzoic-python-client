import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="enzoic",
    version="1.50",
    author="Enzoic",
    author_email="mike@enzoic.com",
    description="Python Client for Enzoic",
    url="https://github.com/Enzoic/enzoic-python-client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=["requests", "pytest", "passlib", "bcrypt", "argon2-cffi==23.1.0"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
