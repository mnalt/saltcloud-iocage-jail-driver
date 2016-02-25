# saltcloud-iocage-jail-driver
Saltcloud driver for using FreeBSD jails with iocage

## Introduction

This is a driver for managing FreeBSD jails with [saltcloud](https://docs.saltstack.com/en/latest/topics/cloud/index.html), using the [iocage](https://github.com/iocage/iocage) scripts.

## Installation
Put the `iocage.py` file in a directory that saltstack will search for cloud drivers. For example, put
    extension_modules: /usr/local/etc/salt/extension_modules
in your `master` configuration file and put the `iocage.py` file in the directory `/usr/local/etc/salt/extension_modules/clouds` directory.

## Configuration
...


