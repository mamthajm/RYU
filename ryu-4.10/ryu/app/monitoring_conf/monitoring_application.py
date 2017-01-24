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
A monitoring application.
"""

import logging
from lxml import etree
from threading import Thread
from ryu.lib.mon_automata.monitoring_switch import MonCapableSwitch
from ryu.lib.mon_automata.mon_agent import MonAgent
from ryu.base import app_manager
import time
import threading

LOG = logging.getLogger(__name__)

class MonitorApplication(app_manager.RyuApp):
     def __init__(self, *args, **kwargs):
         super(MonitorApplication, self).__init__(*args, **kwargs)
         self.node_session_map = {}   #map that contains the switch device ID and its corresponding session information.
         self.no_of_nodes = 0
         self.node_list = []          #list of nodes being monitored.


         #for testing purpose.
         xml =   """<config>
                    <monitoring-model xmlns="http://monitoring-automata.net/sdn-mon-automata" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <state-machines-list nc:operation="create">
                    <mon-id>300</mon-id>
                    <mon-msg-type>MON_HELLO</mon-msg-type>
                    <mon-type>BST</mon-type>
                    <port-index>1</port-index>
                    <poll-time>15000</poll-time>
                    <state-machine>
                    <state-table-id>1</state-table-id>
                    <TotalStates>1</TotalStates>
                    <state-table-row-entries>
                    <state>1</state>
                    <input-events>
                    <row-id>1</row-id>
                    <num_of_row_evnts>2</num_of_row_evnts>
                    <opennslBstStatIdUcast>300</opennslBstStatIdUcast>
                    <opennslBstStatIdMcast>400</opennslBstStatIdMcast>
                    </input-events>
                    <num_of_actions>2</num_of_actions>
                    <action>
                    <A1>NOTIFY_CNTLR</A1>
                    <A2>GOTO_NXT_STATE</A2>
                    </action>
                    <next-state>255</next-state>
                    </state-table-row-entries>
                    </state-machine>
                    </state-machines-list>
                    </monitoring-model>
                    </config>"""
         host_name = '127.0.0.1'
         port_id='830'
         user='shrikanth'
         pwd='sdn123'
         self.monitor_start(xml,host_name,port_id,user,pwd)
         #LOG.info('[MON_START] Monitoring has started')
         #print 'I am here'
         self.start_monitor_thread()  #starts a monitoring thread that receives notifications from the network device.

     def monitor_start(self,xml,host_name,port_id,user,pwd):
          device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters

          if not self.node_session_map.has_key(device_id):           #there is no existing session for the device_id.

                session = MonCapableSwitch(connect_method= 'connect_ssh',
                                           host=host_name, #'localhost'
                                           port=port_id,   #830
                                           username=user,  #'root'
                                           password=pwd,   #'onl'
                                           hostkey_verify=False,allow_agent=False,look_for_keys=False)   # establish the connection.
                device_id = 1 # Remove this later. This is for my testing only.
                self.insert_session_to_map(device_id,session)   # insert the device and its existing session in the session map to be able to retrieve session information later.

                node = MonAgent(device_id)        # Create an object for this node(switch) to store all the monitoring parameters for later retrieval.
                self.node_list.append(node)       # Maintain the list of switches for which monitoring has been started within this list.
                target = 'running'
                config = xml
                session.edit_config(config,target)    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

                mon_agent_id = self.get_mon_agent_id_from_xml(xml)
                node.insert_to_mon_agents_map(mon_agent_id,xml)
          else:
                session = self.get_session_from_map(device_id)
                target = 'running'
                config = xml
                session.edit_config(config,target)    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

                mon_agent_id = self.get_mon_agent_id_from_xml(xml)
                for node_ele in self.node_list:
                    if (node_ele.device_id == device_id):
                        node_ele.insert_to_mon_agents_map(mon_agent_id,xml)        #Insert the monitoring parameters into the map maintained for this device.

     def monitor_stop(self,xml):
         device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters
         session = self.get_session_from_map(device_id)
         session.edit_config('running',xml,'remove')    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.
         mon_agent_id = self.get_mon_agent_id_from_xml(xml)

         for node_ele in self.node_list:
            if (node_ele.device_id == device_id):
                node_ele.remove_from_mon_agents_map(mon_agent_id)   #remove the mon_agent from the map maintained by MonAgent object.
                if len(node_ele.mon_agents_map) == 0:
                    session.close_session()             #if the removed mon_agent is the last node in the map, close the session and
                self.node_list.remove(node_ele)         #remove the node information from the node_list.

     def monitor_param_change(self,xml):
         device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters
         session = self.get_session_from_map(device_id)
         session.edit_config('running',xml,'merge')    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

     def monitor_status_get(self,xml):
         pass

     def monitor_recv_notif(self,device_id):
         session = self.get_session_from_map(device_id)
         #print 'inside the monitor_recev_noitif %s'%session
         notif = session.recv_notification()
         return notif

     def get_session_from_map(self,device_id):
         ret = self.node_session_map.has_key(device_id)
         if ret:
            return self.node_session_map.get(device_id)

     def insert_session_to_map(self,device_id,session):
         self.node_session_map.update({device_id:session})

     def get_device_id_from_xml(self,xml):              #this function shall parse the monitoring parameters supplied by the SDN application that maintains flow information to fetch device-id.
         e_tree = etree.fromstring(xml)
         device_id = e_tree.findtext("device-id")
         return device_id

     def get_mon_agent_id_from_xml(self,xml):          #fetches the mon-id parameter from monitoring parameters.
         e_tree = etree.fromstring(xml)
         mon_agent_id = e_tree.findtext("mon-id")
         return mon_agent_id

     def start_monitor_thread(self):
         new_thread = Thread(target=self.monitor_notifications)
         #new_thread.setDaemon(True)                    #The entire Python program exits when only daemon threads are left
         new_thread.start()
         new_thread.join()
         return

     def monitor_notifications(self):  # monitoring thread that listens to the switches present in the node_list() to get the notification.
        while True:
         #for i in threading.enumerate():
         #  if i.name == "MainThread":
         #    print i.is_alive()
         session_keys = self.node_session_map.keys()          # Get the session keys(device IDs) into a LIST from the MAP (Device ID -> Session Map)
         for node_ele in self.node_list:                       # Run through the LIST of mon_agent(s) populated every first time when there is a new monitoring request for a particular device.
           for device_id in session_keys:                     # Run through the LIST of session_keys.
               if (node_ele.mon_switch_id == device_id):
                  notif = self.monitor_recv_notif(device_id)  # Get the notification from this device.
                  #print 'trying to take a notification %d'% device_id
                  if notif is not None:
                    print notif.notification_xml

