# saltcloud-iocage-jail-driver
Saltcloud driver for using FreeBSD jails with iocage

## Introduction

This is a driver for managing FreeBSD jails with [salt-cloud](https://docs.saltstack.com/en/latest/topics/cloud/index.html), using the [iocage](https://github.com/iocage/iocage) scripts.

It allows you to manage iocage jails on any salt minion. It supports all of the
default salt-cloud functionality and basic iocage features (creation and
deletion of jails, using different templates or releases). In particular the
bootstrap and deployment scripts will be run in the newly created jail (unless
`--no-deploy` is given - see salt-cloud documentation).

Since jails can be accessed from the host, minion keys, configuration and
deployment scripts necessary for bootstrapping are not copied by ssh but using
the salt minion on the host instead. This means that you do not need ssh access
to your newly created jails.


## Installation

Put the `iocage.py` file in a directory that saltstack will search for cloud drivers. For example, put

    extension_modules: /usr/local/etc/salt/extension_modules

in your `master` configuration file and put the `iocage.py` file in the directory `/usr/local/etc/salt/extension_modules/clouds`.



## Configuration

### Provider

Sample provider configuration for a provider named `iocage-example`:

    iocage-example:
      host_list:
        - host1.example.com
	- always.use.complete.minion.id.com
      ignore_host_list:
        - dontuse.example.com
      driver: iocage

The following options are available:
 * `host_list`: lists all minions that should be accessed by salt-cloud. If
   this parameter is not set, all available minions will be used where the
   command `iocage list` can successfully be executed. Always specify the
   complete minion id (usually the fqdn)
 * `ignore_host_list`: remove the named hosts from the list of hosts that will
   be used. Always specify the complete minion id. Only really makes sense if
   no `host_list` is provided (though you can provide both)
 * `driver`: set to `iocage` in order to use this driver

### Profile and Command-Line Parameters

Sample profile configuration:

    profile1:
      provider: iocage-example
      properties:
        ip4_addr: em0|192.168.1.42
      minion:
        master: 192.168.105.2
    profile2:
      provider: iocage-example
      properties:
        ip4_addr: lo1|192.168.105.144
        exec_timeout: 120
      image: "release:9.3-RELEASE"
    profile3:
      provider: iocage-example
        properties:
          ip4_addr: lo1|192.168.105.145
        image: "template:pre-saltet"

The profile configuration allows you to specify the following parameters:

 * `properties`: arbitrary jail properties that iocage supports. In particular,
   you can set the `ip4_addr`.
 
   You must not set the `host_hostname` property, because it will be set to the
   jail name you provide on the command line when calling `salt-cloud`.
 
 * `image`: This parameter is used to specify the release or template to use
   for creating a jail. You can list the available releases and templates using
   the `salt-cloud --list-images=iocage` command.

   To distinguish templates and releases you have to prefix the name with
   `template:` or `release:` respectively.

 * `location`: This specifies the host where you want to create the jail. Use
   the host's minion id.
   You have to specify the `location` if the list of available hosts (see
   `host_list` and `ignore_host_list` above) contains more then one host.

   Alternatively you can provide the location on the command-line using the
   `--location` parameter

In addition to those parameters, you can set most of the default salt-cloud
parameters for profiles, such as `minion` configuration, `script` and
`inline_script`, `file_map` etc (see salt-cloud documentation
[here](https://docs.saltstack.com/en/latest/topics/cloud/misc.html)).  Note
that the iocage driver uses the jail-host's minion to setup the jail, and does
not use ssh to communicate with the jail. The ssh relevant options therefore
have no effect.


Note that jails are identified by iocage tags only. The salt-cloud iocage
currently does not support the use of UUIDs.


