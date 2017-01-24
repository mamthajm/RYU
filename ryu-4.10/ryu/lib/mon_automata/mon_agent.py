# Copyright (C) 2016 TU Darmstadt, Germany
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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""
from libxml2 import outputBuffer
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase
from ryu.lib.ovs.vswitch_idl import *

class MonAgent(app_manager.RyuApp):
    def __init__(self,device_id):
        super(MonAgent, self).__init__()
        self.isEnabled= False
        self.mon_switch_id=device_id
        self.mon_params=None
        self.mon_agents_map= {}
        self.mon_agent_exist = True

    def get_mon_agents_map(self):
        return self.mon_agents_map

    def insert_to_mon_agents_map(self,mon_agent_id,mon_params_xml):
        self.mon_agents_map.update({mon_agent_id:mon_params_xml})

    def remove_from_mon_agents_map(self,mon_agent_id):
        if self.mon_agents_map.has_key(mon_agent_id):
             del self.mon_agents_map[mon_agent_id]

    def get_mon_params_frm_mon_agents_map(self,mon_agent_id):
        if self.mon_agents_map.has_key(mon_agent_id):
             return self.mon_agents_map[mon_agent_id]

    def is_mon_agent_exist(self,mon_agent_id):
        if self.mon_agents_map.has_key(mon_agent_id):
            return True
        else:
            return False

    def set_mon_switch_id(self,mon_switch_id):
        self.mon_switch_id = mon_switch_id

    def get_mon_switch_id(self):
        return self.mon_switch_id

    def get_mon_status(self):
        return self.isEnabled

    def set_mon_status(self,flag):
        self.isEnabled=flag
