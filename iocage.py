import logging
import copy
import uuid
import os
import time
import multiprocessing
import uuid
import re

import salt.config as config
import salt.utils.cloud
import salt.client

from salt.exceptions import (
        SaltCloudConfigError,
        SaltCloudSystemExit
)


__virtualname__ = 'iocage'


log = logging.getLogger(__name__)
_client = salt.client.LocalClient()
_host_list = None



def _parse_key_value_strings_to_dict(string_list, assignment_char='='):
    ret = {}
    for s in string_list:
        (key, value) = s.split(assignment_char,1)
        ret[key] = value
    return ret



class IOCageHostList:

    def __init__(self, provider_options):
        log.info('iocage: discovering hosts')
        self.hosts = dict()

        ignore_host_list = provider_options.get('ignore_host_list', [])
        host_list = provider_options.get('host_list', None)
        if not host_list:
            host_list = '*'
            expr_form = 'glob'
        else:
            if isinstance(host_list, str):
                host_list = [ host_list ]
            expr_form = 'list'

        ret = _client.cmd(host_list, 'cmd.run_all', ['iocage list'], expr_form=expr_form)
        for minion_id, result in ret.items():
            if minion_id in ignore_host_list:
                log.debug('iocage: {} in ignore_host_list - not adding to list of available hosts'.format(minion_id))
                continue
            if result['retcode'] == 0:
                log.debug('iocage seems to be working on {} - adding to host_list'.format(minion_id))
                self.add_host(IOCageHost(minion_id, result['stdout']))
            else:
                log.debug('iocage not available on on {} - not adding to host_list'.format(minion_id))
                log.debug('     "iocage list" returned {}'.format(result))

        log.info('iocage: found {} hosts'.format(len(self.hosts)))


    def is_empty(self):
        return len(self.hosts) == 0


    def add_host(self, host):
        self.hosts[host.minion_id] = host


    def get_minion_ids(self):
        return self.hosts.keys()


    def get_templates(self):
        templates = set()
        for host in self.hosts.values():
            templates.update(host.get_templates())
        return list(templates)


    def get_releases(self):
        releases = set()
        for host in self.hosts.values():
            releases.update(host.get_releases())
        return list(releases)


    def num_hosts(self):
        return len(self.hosts)


    def get_host(self, minion_id):
        return self.hosts.get(minion_id, None)


    def get_first_host(self):
        if self.num_hosts == 0:
            return None
        else:
            return self.hosts.values()[0]


    def list_nodes(self):
        ret = {}
        for host in self.hosts.values():
            ret.update(host.list_nodes())
        return ret


    def list_nodes_full(self):
        ret = {}
        for host in self.hosts.values():
            ret.update(host.list_nodes_full())
        return ret


    def get_jail(self, name):
        for host in self.hosts.values():
            jail = host.get_jail(name)
            if jail != None:
                return jail
        return None


    def destroy_jail(self, name):
        jail = self.get_jail(name)
        if jail != None:
            return jail.destroy()
        else:
            return False



class IOCageHost:
    client = _client


    def __init__(self, minion_id, list_jail_output=None):
        self.minion_id = minion_id
        self.jail_list = None
        self.template_list = None
        self.release_list = None
        if list_jail_output != None:
            self._parse_jail_list(list_jail_output)


    def _execute_salt_module(self, module_function, parameters=()):
        log.debug("iocage - calling {} on {}".format(module_function, self.minion_id))
        ret = self.client.cmd([self.minion_id], module_function, parameters, expr_form='list')
        log.debug("iocage - {} returned {} on {}".format(module_function, repr(ret), self.minion_id))

        if not self.minion_id in ret:
            log.error("iocage - unable to execute {} on iocage host {}".format(module_function, self.minion_id))
            log.debug("client.cmd returned: {}".format(str(ret)))
            return False

        return ret[self.minion_id]


    def execute_command(self, command):
        ret = self._execute_salt_module('cmd.run_all', [command])
        if ret['retcode'] != 0:
            log.debug('iocage: "{}" execution on {} returned {}'.format(command, self.minion_id, ret))
            return False
        else:
            return ret['stdout']

    def write_file(self, dest_path, contents=None, local_file=None, perms='0644'):
        log.info("iocage - writing file {} on '{}'".format(dest_path, self.minion_id))

        # unfortunately we have to work around this bug
        # https://github.com/saltstack/salt/issues/16592
        # which is for salt-cp but also seems to affect file.write, where files that are too large will not get written...
        # it seems the problem has to do with the number of bytes written. For safety, we limit ourselves to 64kb
        # 
        # the rest of the code does something equivalent to this (which does not work due to the bug):
        # ret = _execute_salt_module(target, 'file.write', [dest_path, contents])

        if local_file is not None:
            if os.path.isdir(local_file):
                raise SaltCloudConfigError(
                    'The iocage driver does not support copying directories and {} is a directory'.format(
                        local_file
                    )
                )
            else:
                f = open(local_file, 'r')
                contents = f.read()
                f.close()


        log.debug("iocage - writing file {} on '{}' in multiple chunks".format(dest_path, self.minion_id))
        ret = self._execute_salt_module('file.touch', [dest_path])
        # TODO add more error handling?
        if not ret:
            return False

        i=0
        increment = 64*1024
        while i < len(contents):
            chunk = contents[i:(i+increment)]
            #ret = self._execute_salt_module('file.append', [dest_path, chunk])
            ret = self._execute_salt_module('file.seek_write', [dest_path, chunk, i])
            i += increment
            if ret != len(chunk):
                return False
        log.debug("iocage - DONE writing file {} on '{}' in multiple chunks".format(dest_path, self.minion_id))

        ret = self._execute_salt_module('file.set_mode', [dest_path, perms])

        if not ret:
            return False

        return True


    def mkdir(self, dirname):
        log.debug("iocage - creating directory {} on {}".format(dirname, self.minion_id))
        ret = self._execute_salt_module('file.mkdir', [dirname])
        # TODO add more error handling?
        if not ret:
            return False
        else:
            return True

    def _jail_list_output_valid(self, jail_list_output):
        return jail_list_output == '' or 'JID' in jail_list_output


    def _parse_jail_list(self, jail_list_output):
        self.jail_list =[]

        if jail_list_output == '':
            return self.jail_list

        for jail_line in jail_list_output.split('\n')[1:]:
            if jail_line == '--- non iocage jails currently active ---':
                break
            jail_entry = IOCageJail(None, self)
            jail_entry.parse_list_jail_line(jail_line)
            self.jail_list.append(jail_entry)

        return self.jail_list


    def get_jails(self):
        '''
        returns a list of all jails configured on this host, 
        each jail is represented by a dict containing the fields returned by "iocage list"
        '''
        if self.jail_list == None:
            jail_list_output = self.execute_command('iocage list')
            if not jail_list_output:
                raise SaltCloudSystemExit('Unable to get iocage list output from {}!'.format(self.miniond_id))
            self._parse_jail_list(jail_list_output)
        return self.jail_list


    def get_jail(self, name):
        for jail in self.get_jails():
            if jail.get_tag() == name:
                return jail
        return None
        

    def list_nodes(self):
        '''
        List all jails configured on that host in a format suitable for salt-cloud -Q
        '''

        return { jail.get_id(): jail.list_node() for jail in self.get_jails() } 


    def list_nodes_full(self):
        '''
        List all jails configured on that host in a format suitable for salt-cloud -F
        '''

        return { jail.get_id(): jail.list_node_full() for jail in self.get_jails() } 


    def _parse_interfaces_from_addr_string(self, addr_string):
        if addr_string != None:
            return set([ entry.split('|')[0] for entry in addr_string.split(',') if '|' in entry ])
        else:
            return set()

    def create_jail(self, name, properties, image=None):
        if 'host_hostname' in properties.keys():
            raise SaltCloudConfigError('host_hostname must not be set in properties - the name will be used as hostname!')
        properties['host_hostname'] = name

        # check if interfaces are available on the host
        interfaces = self._parse_interfaces_from_addr_string(properties.get('ip4_addr', None))
        interfaces |= self._parse_interfaces_from_addr_string(properties.get('ip6_addr', None))
        if interfaces:
            existing_ints = self._execute_salt_module('network.interfaces').keys()
            for interface in interfaces:
                if not interface in existing_ints:
                    raise SaltCloudConfigError('you specified an address for interface {} which is not available on host {}'.format(interface, self.minion_id))

        image_type = None

        if image != None:
            # image could be 'template:template-name' or 'release:release-name' or 'just-name'
            tmp = image.split(':')
            if len(tmp) == 1:
                # 'just-name'
                image_name = tmp[0]
                if image_name in self.get_releases():
                    image_type='release'
                elif image_name in self.get_templates():
                    image_type = 'template'
                else:
                    raise SaltCloudConfigError('you specified image "{}" which is not available on host {}'.format(image_name, self.minion_id))
            else:
                image_type = tmp[0]
                image_name = tmp[1]
                if image_type == 'release':
                    if image_name not in self.get_releases():
                        raise SaltCloudConfigError('you specified release "{}" which is not available on host {}'.format(image_name, self.minion_id))
                elif image_type == 'template':
                    if image_name not in self.get_templates():
                        raise SaltCloudConfigError('you specified template "{}" which is not available on host {}'.format(image_name, self.minion_id))
                else:
                    raise SaltCloudConfigError('you specified an image of type "{}" which is unknown (should be "release" or "template")'.format(image_type))

        if image_type == 'release':
            properties[image_type] = image_name


        log.info('iocage - creating jail {} on host {}'.format(name, self.minion_id))
        parameters = ' '.join([ '"{}={}"'.format(key, value) for (key, value) in properties.items() ])
        if image_type == 'template':
            ret = self.execute_command('iocage clone {} tag={} {}'.format(image_name, name, parameters))
            jail_type = 'clonejail'
        else:
            ret = self.execute_command('iocage create tag={} {}'.format(name, parameters))
            jail_type = 'basejail'

        if ret == False:
            log.error("Unable to create jail {} on {}".format(name, self.minion_id))
            return False

        return IOCageJail(name, self, jail_type=jail_type)


    def destroy_jail(self, name):
        jail = self.get_jail(name)
        if jail != None:
            return jail.destroy()
        else:
            return False


    def _remove_jail(self, jail):
        if jail in self.jail_list:
            self.jail_list.remove(jail)
            return True
        else:
            return False

    
    def get_templates(self):
        '''
        returns a list of all templates available on this host, 
        each template is represented by its name (tag)
        '''
        if self.template_list == None:
            self.template_list = []
            template_list_output = self.execute_command('iocage list -t')
            if template_list_output == False:
                raise SaltCloudSystemExit('Unable to get "iocage list -t" output from {}!'.format(self.miniond_id))
            for template_line in template_list_output.split('\n')[1:]:
                fields = re.split('\s+', template_line)
                self.template_list.append(fields[4])

        return self.template_list


    def get_releases(self):
        '''
        returns a list of all releases available on this host, 
        each releases is represented by its name (tag)
        '''
        if self.release_list == None:
            self.release_list = []

            release_list_output = self.execute_command('iocage list -r')
            if release_list_output == False:
                raise SaltCloudSystemExit('Unable to get "iocage list -r" output from {}!'.format(self.miniond_id))
            for release_line in release_list_output.split('\n')[1:]:
                self.release_list.append(release_line.strip())

        return self.release_list


class IOCageJail:

    def __init__(self, tag, host, state='unknown', jail_type=None):
        self.tag = tag
        self.state = state
        self.properties = None
        self.host = host
        self.uuid = None
        self.jail_type = jail_type
        self.image = None

    def parse_list_jail_line(self, line):
        JID=0
        UUID=1
        BOOT=2
        STATE=3
        TAG=4
        TYPE=5

        fields = re.split('\s+', line)
        if self.tag and self.tag != fields[TAG]:
            raise Exception('parse_list_jail_line called with wrong entry - expected tag {}, got {}'.format(self.tag, fields[TAG]))
        self.tag = fields[TAG]
        self.state = fields[STATE]
        self.uuid = fields[UUID]
        self.jail_type = fields[TYPE]
        

    def _get_jail_properties(self):
        log.info('Getting properties for jail {}'.format(self.tag))
        get_properties_output = self.host.execute_command('iocage get all {}'.format(self.tag))
        self.properties = _parse_key_value_strings_to_dict(get_properties_output.split('\n'), ':')


    def get_properties(self):
        if self.properties == None:
            self._get_jail_properties()
        return self.properties
        

    def get_property(self, key):
        return self.get_properties()[key]


    def get_uuid(self):
        if self.uuid == None:
            self.uuid = self.get_property('host_hostuuid')

        return self.uuid


    def get_tag(self):
        return self.tag


    def get_id(self):
        return self.get_tag()


    def get_image(self):

        if self.image == None:
            if self.jail_type == 'basejail':
                self.image  = self.get_property('release')
            elif self.jail_type == 'clonejail':
                # there should be some iocage functionality to do this, but there is none
                # so we call a script to figure out the template this jail was created from
                find_template_script='''
                    source /usr/local/lib/iocage/ioc-info;
                    __find_mypool;
                    uuid=$(iocage get host_hostuuid {});
                    origin=$(zfs get -H -o value origin "$pool/iocage/jails/$uuid");
                    basename "$origin" "@$uuid";
                    '''
                self.image = self.host._execute_salt_module('cmd.exec_code', ['sh', find_template_script.format(self.tag)])
        return self.image

    def get_state(self):
        return self.state

    def get_ips(self):
        ret = []

        ip_addrs = self.get_property('ip4_addr')
        ip_addrs += ',' + self.get_property('ip6_addr')

        for addr in ip_addrs.split(','):
            if addr == 'none':
                continue
            elif '|' in addr:
                ret.append(addr.split('|')[1])
            else:
                ret.append(addr)
        return ret


    def list_node(self):
        return { 
            'id': self.get_id(),
            'image': self.get_image(),
            'size': '',
            'state': self.get_state(),
            'private_ips': [],
            'public_ips': self.get_ips(),
        }


    def list_node_full(self):
        ret = self.list_node()
        ret['location'] = self.host.minion_id
        ret['properties'] = self.get_properties()
        return ret


    def get_jail_root(self):
        return '/iocage/jails/{}/root'.format(self.get_uuid())


    def mkdir(self, dirname):
        self.host.mkdir(self.get_jail_root() + dirname)


    def write_file(self, dest_path, contents=None, local_file=None, perms='0644'):
        self.host.write_file(self.get_jail_root() + dest_path, contents, local_file, perms)


    def execute_command(self, command_line):
        log.debug('iocage - executing command {} in jail {} on host {}'.format(command_line, self.tag, self.host.minion_id))

        # TODO this should be in the iocage execution module!
        ret = self.host._execute_salt_module('cmd.retcode', ['iocage exec {} {}'.format(self.tag, command_line)])
        return ret


    def destroy(self):
        self.stop()

        log.info('iocage - destroying jail {} on host {}'.format(self.get_tag(), self.host.minion_id))

        ret = self.host.execute_command('iocage destroy -f {}'.format(self.get_tag()))
        if ret==False:
            log.error("Unable to destroy {} on {}".format(self.get_tag(), self.host.minion_id))
            return False
        else:
            self.host._remove_jail(self)
            return True

    
    def start(self):
        log.debug('iocage - starting jail {} on host {}'.format(self.tag, self.host.minion_id))
        ret = self.host.execute_command('iocage start {}'.format(self.get_tag()))
        if ret==False:
            log.error("Unable to start {} on {}".format(self.get_tag(), self.host.minion_id))
            return False
        else:
            self.state = 'up'
            return True

    def stop(self):
        log.debug('iocage - stopping jail {} on host {}'.format(self.tag, self.host.minion_id))
        ret = self.host.execute_command('iocage stop {}'.format(self.get_tag()))
        if ret==False:
            log.error("Unable to stop {} on {}".format(self.get_tag(), self.host.minion_id))
            return False
        else:
            self.state = 'down'
            return True


def __virtual__():
    provider_config = get_configured_provider()
    if provider_config is False:
        return False
    else:
        return __virtualname__


def _get_host_list():
    global _host_list
    if _host_list == None:
        _host_list = IOCageHostList(get_configured_provider())
    return _host_list

def get_configured_provider():
    '''
    Return the first configured instance.
    '''
    return config.is_provider_configured(
        __opts__,
        __active_provider_name__ or __virtualname__,
        ()
    )



def create(vm_):

    # TODO if location is set, check if it is a known minion
    target_host = _get_host_list().get_host(__opts__.get('location', None))
    if not target_host:
        target_host = _get_host_list().get_host(vm_.get('location', None))
    if not target_host and _get_host_list().num_hosts() == 1:
        target_host = _get_host_list().get_first_host()

    if not target_host:
        raise SaltCloudConfigError("No host defined for jail {}.\nYou need to provide a location (cli or profile) or have exactly one host available!".format(vm_['name']))

    log.info("Creating iocage jail '{}' on '{}'".format(vm_['name'], target_host.minion_id))

    # fire event salt/cloud/<vm name>/creating
    salt.utils.cloud.fire_event(
        'event', 'starting create',
        'salt/cloud/{0}/creating'.format(vm_['name']),
        {'name': vm_['name'], 'profile': vm_['profile'],
         'provider': vm_['driver'], },
        transport=__opts__['transport'])

    ret = {'name': vm_['name'], 'changes': {}, 'result': True, 'comment': ''}

    # create kwargs

    kwargs={}
    kwargs['name'] = vm_['name']
    kwargs['properties'] = vm_.get('properties', None)
    kwargs['image'] = vm_.get('image', None)

    # fire event salt/cloud/<vm name>/requesting
    salt.utils.cloud.fire_event(
        'event',
        'requesting instance',
        'salt/cloud/{0}/requesting'.format(vm_['name']),
        {'kwargs': kwargs},
        transport=__opts__['transport']
    )

    log.info('Creating jail {}'.format(vm_['name']))
    jail = target_host.create_jail(**kwargs)

    log.info('Starting jail {}'.format(vm_['name']))
    if not jail.start():
        log.error('Unable to start jail {} on '.format(vm_['name'], jail.host.minion_id))
        return False


    bootstrap(vm_, __opts__, jail)

    # fire salt/cloud/<vm name>/created
    salt.utils.cloud.fire_event(
        'event',
        'created instance',
        'salt/cloud/{0}/created'.format(vm_['name']),
        {
            'name': vm_['name'],
            'profile': vm_['profile'],
            'provider': vm_['driver'],
        },
        transport=__opts__['transport']
    )


    # return dict describing vm
    return jail.list_node()



def destroy(name):
    return _get_host_list().destroy_jail(name)


def list_nodes():
    return _get_host_list().list_nodes()


def list_nodes_full():
    return _get_host_list().list_nodes_full()


def list_nodes_select(call=None):
        '''
        Return a list of the VMs that are on the provider, with select fields
        '''
        return salt.utils.cloud.list_nodes_select(
            list_nodes_full(), __opts__['query.selection'], call,
        )


def avail_locations():
    return _get_host_list().get_minion_ids()


def avail_images():
    images = [ 'template:' + t for t in _get_host_list().get_templates()]
    images += [ 'release:' + r for r in _get_host_list().get_releases()]
    return images


def show_instance(name, call=None):
    return _get_host_list().get_jail(name).list_node_full()







################################################################################
# the following functions have been copied from salt.utils.cloud and adapted so 
# they work without ssh
#
# should probably be provided as methods of IOCageJail, but it would be even 
# better to refactor the salt.utils.cloud code to use either ssh or another
# mechanism (such as iocage exec)
################################################################################

def bootstrap(vm_, opts, jail):
    '''
    This is copied and adapted from salt.util.cloud to work without ssh

    This is the primary entry point for logging into any system (POSIX or
    Windows) to install Salt. It will make the decision on its own as to which
    deploy function to call.
    '''
    deploy_config = salt.config.get_cloud_config_value(
        'deploy',
        vm_, opts, default=False)
    inline_script_config = salt.config.get_cloud_config_value(
        'inline_script',
        vm_, opts, default=None)
    if deploy_config is False and inline_script_config is None:
        return {
            'Error': {
                'No Deploy': '\'deploy\' is not enabled. Not deploying.'
            }
        }


    ret = {}

    minion_conf = salt.utils.cloud.minion_config(opts, vm_)
    deploy_script_code = salt.utils.cloud.os_script(
        salt.config.get_cloud_config_value(
            'os', vm_, opts, default='bootstrap-salt'
        ),
        vm_, opts, minion_conf
    )


    # NOTE: deploy_kwargs is also used to pass inline_script variable content
    #       to run_inline_script function
    deploy_kwargs = {
        'opts': opts,
        'salt_host': vm_.get('salt_host', vm_['name']),
        'script': deploy_script_code,
        'inline_script': inline_script_config,
        'name': vm_['name'],
        'tmp_dir': salt.config.get_cloud_config_value(
            'tmp_dir', vm_, opts, default='/tmp/.saltcloud'
        ),
        'deploy_command': salt.config.get_cloud_config_value(
            'deploy_command', vm_, opts,
            default='/tmp/.saltcloud/deploy.sh',
        ),
        'start_action': opts['start_action'],
        'parallel': opts['parallel'],
        'sock_dir': opts['sock_dir'],
        'conf_file': opts['conf_file'],
        'minion_pem': vm_['priv_key'],
        'minion_pub': vm_['pub_key'],
        'master_sign_pub_file': salt.config.get_cloud_config_value(
            'master_sign_pub_file', vm_, opts, default=None),
        'keep_tmp': opts['keep_tmp'],
        'tty': salt.config.get_cloud_config_value(
            'tty', vm_, opts, default=True
        ),
        'script_args': salt.config.get_cloud_config_value(
            'script_args', vm_, opts
        ),
        'script_env': salt.config.get_cloud_config_value(
            'script_env', vm_, opts
        ),
        'minion_conf': minion_conf,
        'preseed_minion_keys': vm_.get('preseed_minion_keys', None),
        'display_ssh_output': salt.config.get_cloud_config_value(
            'display_ssh_output', vm_, opts, default=True
        ),
        'known_hosts_file': salt.config.get_cloud_config_value(
            'known_hosts_file', vm_, opts, default='/dev/null'
        ),
        'file_map': salt.config.get_cloud_config_value(
            'file_map', vm_, opts, default=None
        ),
    }

    inline_script_kwargs = deploy_kwargs

    # Deploy salt-master files, if necessary
    if salt.config.get_cloud_config_value('make_master', vm_, opts) is True:
        deploy_kwargs['make_master'] = True
        deploy_kwargs['master_pub'] = vm_['master_pub']
        deploy_kwargs['master_pem'] = vm_['master_pem']
        master_conf = salt.utils.cloud.master_config(opts, vm_)
        deploy_kwargs['master_conf'] = master_conf

        if master_conf.get('syndic_master', None):
            deploy_kwargs['make_syndic'] = True

    deploy_kwargs['make_minion'] = salt.config.get_cloud_config_value(
        'make_minion', vm_, opts, default=True
    )

    # Store what was used to the deploy the VM
    event_kwargs = copy.deepcopy(deploy_kwargs)
    del event_kwargs['opts']
    del event_kwargs['minion_pem']
    del event_kwargs['minion_pub']
    ret['deploy_kwargs'] = event_kwargs

    salt.utils.cloud.fire_event(
        'event',
        'executing deploy script',
        'salt/cloud/{0}/deploying'.format(vm_['name']),
        {'kwargs': event_kwargs},
        transport=opts.get('transport', 'zeromq')
    )

    if inline_script_config and deploy_config is False:
        inline_script_deployed = run_inline_script(jail, **inline_script_kwargs)
        if inline_script_deployed is not False:
            log.info('Inline script(s) ha(s|ve) run on {0}'.format(vm_['name']))
        ret['deployed'] = False
        return ret
    else:
        deployed = deploy_script(jail, **deploy_kwargs)

        if inline_script_config:
            inline_script_deployed = run_inline_script(jail, **inline_script_kwargs)
            if inline_script_deployed is not False:
                log.info('Inline script(s) ha(s|ve) run on {0}'.format(vm_['name']))

        if deployed is not False:
            ret['deployed'] = True
            if deployed is not True:
                ret.update(deployed)
            log.info('Salt installed on {0}'.format(vm_['name']))
            return ret

    log.error('Failed to start Salt on host {0}'.format(vm_['name']))
    return {
        'Error': {
            'Not Deployed': 'Failed to start Salt on host {0}'.format(
                vm_['name']
            )
        }
    }




def deploy_script(jail,
                  timeout=900,
                  script=None,
                  name=None,
                  sock_dir=None,
                  start_action=None,
                  make_master=False,
                  master_pub=None,
                  master_pem=None,
                  master_conf=None,
                  minion_pub=None,
                  minion_pem=None,
                  minion_conf=None,
                  keep_tmp=False,
                  script_args=None,
                  script_env=None,
                  make_syndic=False,
                  make_minion=True,
                  preseed_minion_keys=None,
                  parallel=False,
                  deploy_command='/tmp/.saltcloud/deploy.sh',
                  opts=None,
                  tmp_dir='/tmp/.saltcloud',
                  file_map=None,
                  master_sign_pub_file=None,
                  **kwargs):
    '''
    Copy a deploy script to a remote server, execute it, and remove it
    '''


    if not isinstance(opts, dict):
        opts = {}

    tmp_dir = '{0}-{1}'.format(tmp_dir.rstrip('/'), uuid.uuid4())
    deploy_command = os.path.join(tmp_dir, 'deploy.sh')
    starttime = time.mktime(time.localtime())
    log.debug('Deploying {0} at {1}'.format(name, starttime))

    if jail.execute_command('test -e \'{0}\''.format(tmp_dir)):
        ret = jail.execute_command(('sh -c "( mkdir -p \'{0}\' &&'
                        ' chmod 700 \'{0}\' )"').format(tmp_dir))
        if ret:
            raise SaltCloudSystemExit(
                'Can\'t create temporary '
                'directory in {0} !'.format(tmp_dir)
            )

    if not isinstance(file_map, dict):
        file_map = {}

    # Copy an arbitrary group of files to the target system
    remote_dirs = []
    file_map_success = []
    file_map_fail = []
    for map_item in file_map:
        local_file = map_item
        remote_file = file_map[map_item]
        if not os.path.exists(map_item):
            log.error(
                'The local file "{0}" does not exist, and will not be '
                'copied to "{1}" on the target system'.format(
                    local_file, remote_file
                )
            )
            file_map_fail.append({local_file: remote_file})
            continue

        if os.path.isdir(local_file):
            dir_name = os.path.basename(local_file)
            remote_dir = os.path.join(os.path.dirname(remote_file),
                                        dir_name)
        else:
            remote_dir = os.path.dirname(remote_file)

        if remote_dir not in remote_dirs:
            jail.execute_command('mkdir -p \'{0}\''.format(remote_dir))
            remote_dirs.append(remote_dir)
        jail.write_file(
            remote_file, local_file=local_file
        )
        file_map_success.append({local_file: remote_file})

    # Minion configuration
    if minion_pem:
        jail.write_file('{0}/minion.pem'.format(tmp_dir), minion_pem)
        ret = jail.execute_command('chmod 600 \'{0}/minion.pem\''.format(tmp_dir))
        if ret:
            raise SaltCloudSystemExit(
                'Cant set perms on {0}/minion.pem'.format(tmp_dir))
    if minion_pub:
        jail.write_file('{0}/minion.pub'.format(tmp_dir), minion_pub)

    if master_sign_pub_file:
        jail.write_file('{0}/master_sign.pub'.format(tmp_dir), local_file=master_sign_pub_file)

    if minion_conf:
        if not isinstance(minion_conf, dict):
            # Let's not just fail regarding this change, specially
            # since we can handle it
            raise DeprecationWarning(
                '`salt.utils.cloud.deploy_script now only accepts '
                'dictionaries for it\'s `minion_conf` parameter. '
                'Loading YAML...'
            )
        minion_grains = minion_conf.pop('grains', {})
        if minion_grains:
            jail.write_file(
                '{0}/grains'.format(tmp_dir),
                salt.utils.cloud.salt_config_to_yaml(minion_grains),
            )
        jail.write_file(
            '{0}/minion'.format(tmp_dir),
            salt.utils.cloud.salt_config_to_yaml(minion_conf),
        )

    # Master configuration
    if master_pem:
        jail.write_file('{0}/master.pem'.format(tmp_dir), master_pem)
        ret = jail.execute_command('chmod 600 \'{0}/master.pem\''.format(tmp_dir))
        if ret:
            raise SaltCloudSystemExit(
                'Cant set perms on {0}/master.pem'.format(tmp_dir))

    if master_pub:
        jail.write_file('{0}/master.pub'.format(tmp_dir), master_pub)

    if master_conf:
        if not isinstance(master_conf, dict):
            # Let's not just fail regarding this change, specially
            # since we can handle it
            raise DeprecationWarning(
                '`salt.utils.cloud.deploy_script now only accepts '
                'dictionaries for it\'s `master_conf` parameter. '
                'Loading from YAML ...'
            )

        ssh_file(
            '{0}/master'.format(tmp_dir),
            salt.utils.cloud.salt_config_to_yaml(master_conf),
        )

    # XXX: We need to make these paths configurable
    preseed_minion_keys_tempdir = '{0}/preseed-minion-keys'.format(
        tmp_dir)
    if preseed_minion_keys is not None:
        # Create remote temp dir
        ret = jail.execute_command(
            'mkdir \'{0}\''.format(preseed_minion_keys_tempdir)
        )
        if ret:
            raise SaltCloudSystemExit(
                'Cant create {0}'.format(preseed_minion_keys_tempdir))
        ret = jail.execute_command(
            'chmod 700 \'{0}\''.format(preseed_minion_keys_tempdir)
        )
        if ret:
            raise SaltCloudSystemExit(
                'Cant set perms on {0}'.format(
                    preseed_minion_keys_tempdir))

        # Copy pre-seed minion keys
        for minion_id, minion_key in six.iteritems(preseed_minion_keys):
            rpath = os.path.join(
                preseed_minion_keys_tempdir, minion_id
            )
            jail.write_file(rpath, minion_key)

    # The actual deploy script
    if script:
        # got strange escaping issues with sudoer, going onto a
        # subshell fixes that
        jail.write_file('{0}/deploy.sh'.format(tmp_dir), script)
        ret = jail.execute_command(
            ('sh -c "( chmod +x \'{0}/deploy.sh\' )";'
                'exit $?').format(tmp_dir))
        if ret:
            raise SaltCloudSystemExit(
                'Cant set perms on {0}/deploy.sh'.format(tmp_dir))

    newtimeout = timeout - (time.mktime(time.localtime()) - starttime)
    queue = None
    process = None
    # Consider this code experimental. It causes Salt Cloud to wait
    # for the minion to check in, and then fire a startup event.
    # Disabled if parallel because it doesn't work!
    if start_action and not parallel:
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=check_auth, kwargs=dict(
                name=name, sock_dir=sock_dir,
                timeout=newtimeout, queue=queue
            )
        )
        log.debug('Starting new process to wait for salt-minion')
        process.start()

    # Run the deploy script
    if script:
        if 'bootstrap-salt' in script:
            deploy_command += ' -c \'{0}\''.format(tmp_dir)
            if make_syndic is True:
                deploy_command += ' -S'
            if make_master is True:
                deploy_command += ' -M'
            if make_minion is False:
                deploy_command += ' -N'
            if keep_tmp is True:
                deploy_command += ' -K'
            if preseed_minion_keys is not None:
                deploy_command += ' -k \'{0}\''.format(
                    preseed_minion_keys_tempdir
                )
        if script_args:
            deploy_command += ' {0}'.format(script_args)

        if script_env:
            if not isinstance(script_env, dict):
                raise SaltCloudSystemExit(
                    'The \'script_env\' configuration setting NEEDS '
                    'to be a dictionary not a {0}'.format(
                        type(script_env)
                    )
                )
            environ_script_contents = ['#!/bin/sh']
            for key, value in six.iteritems(script_env):
                environ_script_contents.append(
                    'setenv {0} \'{1}\' >/dev/null 2>&1 || '
                    'export {0}=\'{1}\''.format(key, value)
                )
            environ_script_contents.append(deploy_command)

            # Upload our environ setter wrapper
            ssh_file(
                '{0}/environ-deploy-wrapper.sh'.format(tmp_dir),
                '\n'.join(environ_script_contents),
            )
            jail.execute_command(
                'chmod +x \'{0}/environ-deploy-wrapper.sh\''.format(tmp_dir)
            )
            # The deploy command is now our wrapper
            deploy_command = '\'{0}/environ-deploy-wrapper.sh\''.format(
                tmp_dir,
            )
        if jail.execute_command(deploy_command) != 0:
            raise SaltCloudSystemExit(
                'Executing the command {0!r} failed'.format(
                    deploy_command
                )
            )
        log.debug('Executed command {0!r}'.format(deploy_command))

        # Remove the deploy script
        if not keep_tmp:
            jail.execute_command('rm -f \'{0}/deploy.sh\''.format(tmp_dir))
            log.debug('Removed {0}/deploy.sh'.format(tmp_dir))
            if script_env:
                jail.execute_command(
                    'rm -f \'{0}/environ-deploy-wrapper.sh\''.format(
                        tmp_dir
                    ) 
                )
                log.debug(
                    'Removed {0}/environ-deploy-wrapper.sh'.format(
                        tmp_dir
                    )
                )

    if keep_tmp:
        log.debug(
            'Not removing deployment files from {0}/'.format(tmp_dir)
        )
    else:
        # Remove minion configuration
        if minion_pub:
            jail.execute_command('rm -f \'{0}/minion.pub\''.format(tmp_dir))
            log.debug('Removed {0}/minion.pub'.format(tmp_dir))
        if minion_pem:
            jail.execute_command('rm -f \'{0}/minion.pem\''.format(tmp_dir))
            log.debug('Removed {0}/minion.pem'.format(tmp_dir))
        if minion_conf:
            jail.execute_command('rm -f \'{0}/grains\''.format(tmp_dir))
            log.debug('Removed {0}/grains'.format(tmp_dir))
            jail.execute_command('rm -f \'{0}/minion\''.format(tmp_dir))
            log.debug('Removed {0}/minion'.format(tmp_dir))
        if master_sign_pub_file:
            jail.execute_command('rm -f {0}/master_sign.pub'.format(tmp_dir))
            log.debug('Removed {0}/master_sign.pub'.format(tmp_dir))

        # Remove master configuration
        if master_pub:
            jail.execute_command('rm -f \'{0}/master.pub\''.format(tmp_dir))
            log.debug('Removed {0}/master.pub'.format(tmp_dir))
        if master_pem:
            jail.execute_command('rm -f \'{0}/master.pem\''.format(tmp_dir))
            log.debug('Removed {0}/master.pem'.format(tmp_dir))
        if master_conf:
            jail.execute_command('rm -f \'{0}/master\''.format(tmp_dir))
            log.debug('Removed {0}/master'.format(tmp_dir))

        # Remove pre-seed keys directory
        if preseed_minion_keys is not None:
            jail.execute_command(
                'rm -rf \'{0}\''.format(
                    preseed_minion_keys_tempdir
                )
            )
            log.debug(
                'Removed {0}'.format(preseed_minion_keys_tempdir)
            )

    if start_action and not parallel:
        queuereturn = queue.get()
        process.join()
        if queuereturn and start_action:
            # client = salt.client.LocalClient(conf_file)
            # output = client.cmd_iter(
            # name, 'state.highstate', timeout=timeout
            # )
            # for line in output:
            #    print(line)
            log.info(
                'Executing {0} on the salt-minion'.format(
                    start_action
                )
            )
            jail.execute_command(
                'salt-call {0}'.format(start_action)
            )
            log.info(
                'Finished executing {0} on the salt-minion'.format(
                    start_action
                )
            )
    # Fire deploy action
    salt.utils.cloud.fire_event(
        'event',
        '{0} has been deployed at {1}'.format(name, jail.host.minion_id),
        'salt/cloud/{0}/deploy_script'.format(name),
        {
            'name': name,
            'host': jail.host.minion_id
        },
        transport=opts.get('transport', 'zeromq')
    )
    if file_map_fail or file_map_success:
        return {
            'File Upload Success': file_map_success,
            'File Upload Failure': file_map_fail,
        }
    return True


def run_inline_script(jail,
                      name=None,
                      port=22,
                      timeout=900,
                      username='root',
                      key_filename=None,
                      inline_script=None,
                      ssh_timeout=15,
                      display_ssh_output=True,
                      parallel=False,
                      sudo_password=None,
                      sudo=False,
                      password=None,
                      tty=None,
                      opts=None,
                      tmp_dir='/tmp/.saltcloud-inline_script',
                      **kwargs):
    '''
    Run the inline script commands, one by one
    :**kwargs: catch all other things we may get but don't actually need/use
    '''

    starttime = time.mktime(time.localtime())
    log.debug('Deploying {0} at {1}'.format(jail.host.minion_id, starttime))

    known_hosts_file = kwargs.get('known_hosts_file', '/dev/null')

    if jail.execute_command('test -e \\"{0}\\"'.format(tmp_dir)):
        if inline_script:
            log.debug('Found inline script to execute.')
            for cmd_line in inline_script:
                log.info("Executing inline command: " + str(cmd_line))
                ret = jail.execute_command('sh -c "( {0} )"'.format(cmd_line))
                if ret:
                    log.info("[" + str(cmd_line) + "] Output: " + str(ret))

    # TODO: ensure we send the correct return value
    return True





