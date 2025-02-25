from setuptools import setup, find_packages


setup(
    name='bitterlich',
    version='0.0.1',
    description='CLI tool for creating secure data vaults',
    author='NaroMori',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'click',
        'cryptography',
        'configparser'
    ],
    entry_points={
        'console_scripts': [
            'bitterl=bitterlich.cli:entry',
        ],
    },
)