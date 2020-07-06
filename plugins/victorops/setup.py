
from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name="alerta-victorops",
    version=version,
    description='Alerta plugin for VictorOps',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Ryan Addessi',
    author_email='ryan.addessi@protonmail.com',
    packages=find_packages(),
    py_modules=['alerta_victorops'],
    install_requires=[
        'requests'
    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'victorops = alerta_victorops:TriggerEvent'
        ]
    }
)
