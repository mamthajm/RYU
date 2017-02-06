# Copyright (C) 2016 TU Darmstadt, Germany.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ncclient
import ncclient.manager
import ncclient.xml_
import logging
LOG = logging.getLogger(__name__)

class MonCapableSwitch(object):
    def __init__(self, connect_method='connect_ssh', *args, **kwargs):
        super(MonCapableSwitch, self).__init__()
        self._connect_method = connect_method
        self._connect_args = args
        self._connect_kwargs = kwargs
        self.version = None
        self.namespace = None

        connect = getattr(ncclient.manager, self._connect_method)
        self.netconf = connect(*self._connect_args, **self._connect_kwargs)
        self.subscribe()

    def close_session(self):
        if self.netconf:
            self.netconf.close_session()
            self.netconf = None

    def __enter__(self):
        return self

    def __exit__(self):
        self.close_session()

    def client_capabilities(self):
        return self.netconf.client_capabilities

    def server_capabilities(self):
        return self.netconf.server_capabilities

    def raw_get_config(self, source, filter=None):
        return self.netconf.get_config(source, filter)

    def raw_edit_config(self, target, config, default_operation=None,
                        test_option=None, error_option=None):
        self.netconf.edit_config(target,config)

    def get_config(self, source):
        return self.raw_get_config(source)

    def edit_config(self,config,target):
        try:
         self.netconf.edit_config(config,target='running')
        except:
           LOG.info("Could not make the connection!!!")

    def subscribe(self):
        self.netconf.create_subscription()

#This is only a test function to check on the NETCONF server.
    def rpc_mon_stop(self,config):
        print config
        rpc_reply = self.netconf.mon_stop(config)
        return rpc_reply

    def rpc_mon_status(self,config):
        print 'in rpc mon_status'
        rpc_reply = self.netconf.mon_status(config)
        return rpc_reply

    def rpc_get_port_statistics(self,config):
        print config
        rpc_reply = self.netconf.port_statistics(config)
        print rpc_reply
        return rpc_reply

    def rpc_get_bst_statistics(self,config):
        print config
        rpc_reply = self.netconf.get_bst_statistics(config)
        return rpc_reply

    #def rpc_get_bst_statistics(self,config):
    #    print config
    #     rpc_reply = self.netconf.get_bst_statistics(config)
    #    return rpc_reply

    def rpc_get_field_processor_group_status(self,config):
        print config
        rpc_reply = self.netconf.get_field_processor_group_status(config)
        return rpc_reply

    def recv_notification(self):
        try:
            ret= self.netconf.take_notification(block=True,timeout=2)
            return ret
        except:
             LOG.info('Some exception occured while receving the notification')
