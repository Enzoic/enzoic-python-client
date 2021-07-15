import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='enzoic',
    version='1.0',
    author="Jeffrey Kasser",
    author_email="jeff@enzoic.com",
    description="Python Client for Enzoic",
    url='https://github.com/Enzoic/enzoic-python-client',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=[
        'requests',
        'argon2-cffi',
        'pytest',
        'whirlpool',
        'passlib'
    ],
    classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
 )