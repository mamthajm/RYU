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
A monitoring application. Uses ncclient library that is available with the code repository.
"""

import logging
from lxml import etree
from threading import Thread
from ryu.lib.mon_automata.monitoring_switch import MonCapableSwitch
from ryu.lib.mon_automata.mon_agent import MonAgent
from ryu.base import app_manager
import xml.etree.ElementTree as ET
import time
from ryu.lib import hub
import threading
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import re
from sys import getsizeof

LOG = logging.getLogger(__name__)

class MonitorApplication(app_manager.RyuApp):


     def __init__(self, *args, **kwargs):
         super(MonitorApplication, self).__init__(*args, **kwargs)
	 print('mon hell')
         self.node_session_map = {}   #map that contains the switch device ID and its corresponding SSH session information.
         self.no_of_nodes = 0
         self.node_list = []          #list of nodes being monitored.
         self.mon_started = False
         self.time_diff = []
         self.monitor_thread = 0
         if self.mon_started is False:
            self.monitor_thread = hub.spawn(self.monitor_notifications())  #starts a monitoring thread that receives notifications from the network device.
            self.mon_started=True

#This function is just to ensure that the main thread stays alive in an event loop while the monitoring thread is working on receiving notifications.
     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
     def dummy_packetIn_handle(self):
         pass


#Below function is used to trigger the monitoring stop requests from other RYU applications that maintain traffic flows.
     def monitor_start(self,xml,host_name,port_id,user,pwd):

          tree = self.remove_white_spaces_from_xml_string(xml)  #xml is received as a string at this point.
          xml_without_ns = xml  #copy the contents of the XML string that will be pushed onto the map maintained by the mon_angent object for this device.
          new_tree = self.parse_tree_and_update_attributes(tree,"monitoring-model","xmlns","http://monitoring-automata.net/sdn-mon-automata")
          new_tree = self.parse_tree_and_update_attributes(new_tree,"monitoring-model","xmlns:nc","urn:ietf:params:xml:ns:netconf:base:1.0")
          new_tree = self.parse_tree_and_update_attributes(new_tree,"monitoring-agent","nc:operation","create")
          xml = ET.tostring(new_tree)

          device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters
          if not self.node_session_map.has_key(device_id):           #there is no existing session for the device_id.
                print 'Creating new MonCapableSwitch object'
                session = MonCapableSwitch(connect_method= 'connect_ssh',
                                           host=host_name, #'localhost'
                                           port=port_id,   #830
                                           username=user,  #'root'
                                           password=pwd,   #'onl'
                                           device_params = {'name':'tud'},
                                           hostkey_verify=False,allow_agent=False,look_for_keys=False)   # establish the connection.

                self.insert_session_to_map(device_id,session)   # insert the device and its existing SSH session into the session map to be able to retrieve SSH session information later.

                node = MonAgent(device_id)        # Create an object for this node(switch) to store all the monitoring parameters for later retrieval.
                self.node_list.append(node)       # Maintain the list of switches for which monitoring has been started.
                target = 'running'
                config = xml
                session.edit_config(config,target)    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

                mon_agent_id = self.get_mon_agent_id_from_xml(xml)
                print 'monitoring agent ID decoded as %r'%mon_agent_id
                node.insert_to_mon_agents_map(mon_agent_id,xml_without_ns)   #Insert the monitoring parameters into the switch object. xml_without_ns is in XML form and not in String form.

          else:
                LOG.info('Monitoring agent already exist, so using that session')
                session = self.get_session_from_map(device_id)
                target = 'running'
                config = xml
                session.edit_config(config,target)    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

                mon_agent_id = self.get_mon_agent_id_from_xml(xml)
                for node_ele in self.node_list:
                    if (node_ele.device_id == device_id):
                        node_ele.insert_to_mon_agents_map(mon_agent_id,xml_without_ns)        #Insert the monitoring parameters into the map maintained for this device.

#Below function is used to trigger the monitoring start requests from other RYU applications that maintain traffic flows.
     def monitor_stop(self,xml):
         device_id = self.get_device_id_from_xml(xml)        #get the device ID from the monitoring parameters
         session = self.get_session_from_map(device_id)
         config = xml
         target = 'running'
         session.edit_config(config,target)    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.
         mon_agent_id = self.get_mon_agent_id_from_xml(xml)

         for node_ele in self.node_list:
            if (node_ele.mon_switch_id == device_id):
                node_ele.remove_from_mon_agents_map(mon_agent_id)   #remove the mon_agent from the map maintained by MonAgent object which containt moniroting configuration.
                if len(node_ele.mon_agents_map) == 0:
                    session.close_session()             #if the removed mon_agent is the last node in the map, close the session and
                    del self.node_session_map[device_id]    # remove the session that exist for this device_id also.
                self.node_list.remove(node_ele)         #remove the node information from the node_list.

#Below function is used to trigger the monitoring parameter change requests from other RYU applications that maintain traffic flows.
     def monitor_param_change(self,xml):
         device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters
         session = self.get_session_from_map(device_id)
         session.edit_config('running',xml,'merge')    # start the monitoring agent on the switch by pushing appropriate monitoring parameters.

#Below function is used to trigger the monitoring status get requests from other RYU applications that maintain traffic flows.
     def monitor_status_get(self,xml):  #used to get the monitoring status from a monitoring agent using the RPC.
         device_id = self.get_device_id_from_xml(xml)  #get the device ID from the monitoring parameters
         session = self.get_session_from_map(device_id)
         config = xml
         rpc_reply = session.rpc_mon_status(config)
         return  rpc_reply

#Below function is used to trigger receive notification requests.
     def monitor_recv_notif(self,device_id):
         session = self.get_session_from_map(device_id)
         #print 'inside the monitor_recev_noitif %s'%session
         notif = session.recv_notification()
         return notif

#Below function is used to maintain device to SSH-session map to be able to commmunicate with the devices.
     def get_session_from_map(self,device_id):
         ret = self.node_session_map.has_key(device_id)
         if ret:
            return self.node_session_map.get(device_id)

     def insert_session_to_map(self,device_id,session):
         self.node_session_map.update({device_id:session})

     def get_device_id_from_xml(self,xml):              #this function shall parse the monitoring parameters supplied by the SDN application that maintains flow information to fetch device-id.
         tree = self.remove_white_spaces_from_xml_string(xml)
         device_id = self.remove_namespace_get_element_text(tree,"http://monitoring-automata.net/sdn-mon-automata","device-id")
         print 'device extracted is %r'%device_id
         return device_id

     def get_mon_agent_id_from_xml(self,xml):          #fetches the mon-id parameter from monitoring parameters.
         tree = self.remove_white_spaces_from_xml_string(xml)
         mon_agent_id = self.remove_namespace_get_element_text(tree,"http://monitoring-automata.net/sdn-mon-automata","mon-id")
         print 'Monitoring agent id extracted is %r'%mon_agent_id
         return mon_agent_id


     #def start_monitor_thread(self):
         #new_thread = Thread(target=self.monitor_notifications)
         #new_thread.setDaemon(True)                    #The entire Python program exits when only daemon threads are left
         #new_thread.start()
         #return

#call the function remove_white_spaces_from_xml_string before invoking this to ensure there are no white spaces in the XML string
     def remove_namespace_get_element_text(self,doc, namespace,element):
        """Remove namespace in the passed document in place and return the requested element's content"""
        ns = u'{%s}' % namespace
        nsl = len(ns)
        for elem in doc.getiterator():
            if elem.tag.startswith(ns):
                elem.tag = elem.tag[nsl:]
                if elem.tag == element:   #Returns the element's text from here. For ex: device id could be fetched from here.
                    return elem.text

#Given an XML tree string ,as in testcases function, removes all the unwanted whitespaces from the string.
     def remove_white_spaces_from_xml_string(self,xml):
        xml_nospace = xml
        parser = etree.XMLParser(remove_blank_text=True)
        elem = etree.XML(xml_nospace, parser=parser) #Returns element object.
        string_elem = ET.tostring(elem)
        tree = ET.fromstring(string_elem)  #parse the XML using fromstring function. Has an element attribute in tree variable now ==> Points to Config element.
        return tree

#Create the monitoring status element.
     def create_monitoring_status_sub_tree(self,statPackets,statBytes):
        new_elem = ET.Element('monitoring-status')
        #new_elem.set("xmlns","http://monitoring-automata.net/sdn-mon-automata")
        packet_elem = ET.SubElement(new_elem,'stat-packets')
        packet_elem.text = statPackets                      #Copy the number of packets accounted so far by the first switch on which we are going to stop Monitoring.
        bytes_elem = ET.SubElement(new_elem,'stat-bytes')
        bytes_elem.text = statBytes                         #Copy the number of Bytes accounted so far by the switch on which we are goint to stop Monitoring.
        return new_elem

#Below function will append the Monitoring status to the MONITORING AGENT that needs to be moved on to the new switch
    # def parse_tree_and_update_mon_status(self,doc,namespace,new_elem):
    #    """Remove namespace in the passed document in place."""
    #    ns = u'{%s}' % namespace
    #    nsl = len(ns)
    #    for elem in doc.getiterator():
    #        if elem.tag.startswith(ns):
    #            #print elem.tag
    #            #elem.tag = elem.tag[nsl:]
    #            if elem.tag[nsl:] == "state-table-row-entries":
    #                elem.append(new_elem)
    #    return doc


#Below function will append the Monitoring status to the MONITORING AGENT that needs to be moved on to the new switch
     def parse_tree_and_update_attributes(self,doc,element,attr_key,attr_val):
        """Remove namespace in the passed document in place."""
        for elem in doc.getiterator():
            if elem.tag == element:
                elem.set(attr_key,attr_val)
        return doc                                                  #Return the document that contains the monitoring status appended.

#Below function will append the Monitoring status to the MONITORING AGENT that needs to be moved on to the new switch
     def parse_tree_and_update_mon_status(self,doc,new_elem):
        """Remove namespace in the passed document in place.
           Input is an XML doc and an element/subtree that should be appended"""
        for elem in doc.getiterator():
                if elem.tag == "state-table-row-entries":
                    elem.append(new_elem)
        return doc                                                  #Return the document that contains the monitoring status appended.

     def remove_namespace(self,doc, namespace):
        """Remove namespace in the passed document in place."""
        ns = u'{%s}' % namespace
        nsl = len(ns)
        for elem in doc.getiterator():
            if elem.tag.startswith(ns):
                elem.tag = elem.tag[nsl:]
        return doc

#This function is used to check if the received notification is a MON_SWITCH_NOTIFICATION.
     def check_for_mon_switch_notification(self,notif,namespace):
        ns = u'{%s}' % namespace
        nsl = len(ns)
        for elem in notif.getiterator():
            if elem.tag.startswith(ns):
                elem.tag = elem.tag[nsl:]
                if elem.tag == "MON_SWITCH":
                    return True

#This function is used to CREATE the 'mon_status' RPC request message to be sent to the switch.
     def create_mon_status_msg(self,mon_id,dev_id):
        new_elem = ET.Element('mon_status')
        new_elem.set("xmlns","http://monitoring-automata.net/sdn-mon-automata")
        packet_elem = ET.SubElement(new_elem,'mon-id')
        packet_elem.text = str(mon_id)                    #Copy the number of packets accounted so far by the first switch on which we are going to stop Monitoring.)
        bytes_elem = ET.SubElement(new_elem,'device-id')
        bytes_elem.text = str(dev_id)                         #Copy the number of Bytes accounted so far by the switch on which we are goint to stop Monitoring.
        return ET.tostring(new_elem)


#This function is used to CREATE the 'mon_stop' request message to be sent to the switch.
     def create_mon_stop_msg(self,mon_id,dev_id):
        """Creates and returns the mon_stop message in string format"""
        config_elem = ET.Element('config')
        new_elem = ET.SubElement(config_elem,'monitoring-model')
        new_elem.set("xmlns","http://monitoring-automata.net/sdn-mon-automata")
        new_elem.set("xmlns:nc","urn:ietf:params:xml:ns:netconf:base:1.0")
        st_machine_list_ele = ET.SubElement(new_elem,"monitoring-agent")
        st_machine_list_ele.set("nc:operation","remove")
        mon_id_elem = ET.SubElement(st_machine_list_ele,'mon-id')
        mon_id_elem.text = mon_id                     #Copy the number of packets accounted so far by the first switch on which we are going to stop Monitoring.
        dev_id_elem = ET.SubElement(st_machine_list_ele,'device-id')
        dev_id_elem.text = dev_id                    #Copy the number of Bytes accounted so far by the switch on which we are goint to stop Monitoring.
        #print ET.dump(config_elem)
        return ET.tostring(config_elem)
        #xml = """<config>
        #         <monitoring-model xmlns="http://monitoring-automata.net/sdn-mon-automata" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        #         <state-machines-list nc:operation = "remove">
        #         <mon-id>500</mon-id>
        #         <device-id>10</device-id>
        #         </state-machines-list>
        #          </monitoring-model>
        #         </config>""" #%(mon_id,dev_id)
        #xml_tree = etree.fromstring(xml)
        #print xml #etree.dump(xml_tree)
        #return xml

#Find the device-id element and modify with new content
     def modify_mon_params_with_new_dev_id(self,new_mon_params,dev_id):
         """Update the monitoring parameters with new device id"""
         for elem in new_mon_params.getiterator():
            if elem.tag == 'device-id':
               elem.text = dev_id
         return new_mon_params



     def get_mon_agent_to_transfer(self,dev_id):
         """Some algorithm that decides on which monitoring agent should be moved
            to other swithch shall run here, hardcoded value returned at the moment"""
         return str(5)


     def get_new_device_to_transfer_the_agent(self):
         """This function returns the appropriate switch device onto which monitoring agent should be transferred"""
         return str(20)    #Hardcode the device-id for time being. Assign this Accton AS7712 switch

#simple function TO RUN VARIOUS TESTCASES.
     def testcases(self):
            #xml = """<mon_stop xmlns="http://monitoring-automata.net/sdn-mon-automata"><mon-id>500</mon-id><mon-msg-type>MON_STOP</mon-msg-type></mon_stop>""" #remove this later
            #config=xml
            #session.rpc_mon_stop(config) ## Remove these lines later. This is just to show case that rpc operation is done this way.
            #print 'mon_stop triggered'

         #For testing purpose. This is to test appending the mon-status to send it to other switch.
         xml =   """<config>
                    <monitoring-model>
                    <monitoring-agent>
                    <mon-id>5</mon-id>
                    <mon-msg-type>MON_HELLO</mon-msg-type>
                    <device-id>10</device-id>
                    <mon-type>FP</mon-type>
                    <port-index>2</port-index>
                    <poll-time>10</poll-time>
                    <state-machine>
                    <TotalStates>1</TotalStates>
                    <state-table-row-entries>
                    <state>1</state>
                    <input-events>
                    <num_of_row_evnts>0</num_of_row_evnts>
                    </input-events>
                    <flow_to_install>
                    <src_ip>50.0.0.5</src_ip>
                    <dst_ip>20.1.1.2</dst_ip>
                    <src_ip_mask>255.255.255.255</src_ip_mask>
                    <dst_ip_mask>255.255.255.255</dst_ip_mask>
                    </flow_to_install>
                    <num_of_actions>1</num_of_actions>
                    <action>
                    <A1>NO_ACTION</A1>
                    </action>
                    <next-state>255</next-state>
                    </state-table-row-entries>
                    </state-machine>
                    </monitoring-agent>
                    </monitoring-model>
                    </config>"""

         host_name = '192.168.0.105' #This should be localhost if the NETCONF server is running on a ubuntu machine
         port_id='830'
         user='root' 		   #This will change according to where NETCONF server is running, root and onl is for logging into the switch
         pwd='onl'


         tree = self.remove_white_spaces_from_xml_string(xml)
         #new_elem = self.create_monitoring_status_sub_tree('10','640')   #hardcode the values for time being.Need to get these values from the MON_STATUS returned by the switch.
         #new_tree = self.parse_tree_and_update_mon_status(tree,new_elem)
         xml_string = ET.tostring(tree)


         #below three lines are not at all required. Do not look at them again.
         #new_tree = self.parse_tree_and_update_attributes(new_tree,"monitoring-model","xmlns","http://monitoring-automata.net/sdn-mon-automata")
         #new_tree = self.parse_tree_and_update_attributes(new_tree,"monitoring-model","xmlns:nc","urn:ietf:params:xml:ns:netconf:base:1.0")
         #new_tree = self.parse_tree_and_update_attributes(new_tree,"state-machines-list","nc:operation","create")


         print "\n\n Newly composed XML Content is \n\n %s "%xml_string
         self.monitor_start(xml_string,host_name,port_id,user,pwd)

         xml = """<mon_status xmlns="http://monitoring-automata.net/sdn-mon-automata"><mon-id>500</mon-id><device-id>10</device-id></mon_status>""" #remove this later
         LOG.info( 'mon_status triggered')
         rpc_reply = self.monitor_status_get(xml)## Remove these lines later. This is just to show case that rpc operation is done this way.
         LOG.info('\n Received monitoring status %s'% rpc_reply)

#Monitoring thread that receives async notifications from the switches and handles Monitoring agent movement.
     def monitor_notifications(self):  # monitoring thread that listens to the switches present in the node_list() to get the notification.
        self.testcases()             #this is to run test cases

        while True:
         #hub.sleep(1)
         #f = open('/time_difference.dat', 'w')
         session_keys = self.node_session_map.keys()          # Get the session keys(device IDs) into a LIST from the MAP (Device ID -> Session Map)
         for node_ele in self.node_list:                       # Run through the LIST of mon_agent(s) populated every first time when there is a new monitoring request for a particular device.
           for device_id in session_keys:                     # Run through the LIST of session_keys.
               if (node_ele.mon_switch_id == device_id):
                  notif = self.monitor_recv_notif(device_id)  # Get the notification from this device.
                  LOG.info('\n Trying to receive notification from the device %r'% device_id)
                  if notif is not None:
                    #print notif.notification_xml
                    notif_xml = ET.fromstring(notif.notification_xml) #conversion form string to xml
                    packet_size = len(notif.notification_xml.encode('utf8'))
                    print 'packet size: ', packet_size
                    #print 'printing tree of xml'
                    #print notif_xml[1].tag
                    root_check = notif_xml[1].tag
                    if 'MON_EVENT_NOTIFICATION' in root_check:
                        timestamp_val = int(notif_xml[1][4].text)
                        packet_number = int(notif_xml[1][5].text)
                        current_millis = int(round(time.time() * 1000))
                        print 'Timestamp value : ', timestamp_val
                        print 'Current time:', current_millis
                        print 'packet number:', packet_number
                        time_diff = int(current_millis - timestamp_val)
                        #f.write(str(time_diff)+'\n')
                        self.time_diff.append(time_diff)
                        print 'Time diff', self.time_diff
                        #f.close()
                    #print ET.dump(notif_xml)
                    is_mon_switch = self.check_for_mon_switch_notification(notif_xml,"http://monitoring-automata.net/sdn-mon-automata")
                    if is_mon_switch == True: #if the received message notification is to switch the agents then run the below algorithm.

                         dev_id = self.remove_namespace_get_element_text(notif_xml,"http://monitoring-automata.net/sdn-mon-automata","device-Id") #The string device-Id is same as it is encoded on the switch side.
                         tcam_count = self.remove_namespace_get_element_text(notif_xml,"http://monitoring-automata.net/sdn-mon-automata","TCAM-Count")
                         min_free_entry_dev = self.remove_namespace_get_element_text(notif_xml,"http://monitoring-automata.net/sdn-mon-automata","min-Free-Entry-Count")
                         max_allowed_tcam_entries = self.remove_namespace_get_element_text(notif_xml,"http://monitoring-automata.net/sdn-mon-automata","TCAM-threshold-set") #maximum allowed for monitoring.

                         LOG.info('\n Received MON_SWITCH notification for device %r'%dev_id)
                         LOG.info('\n Received MON_SWITCH notification TCAM count used %r'%tcam_count)
                         LOG.info('\n Received MON_SWITCH notification MINUIMUM number of free entries for other purposes than monitorin %r'%min_free_entry_dev)
                         LOG.info('\n Received MON_SWITCH notification Threshold on the device %r'%max_allowed_tcam_entries)

                         ssh_dev_session = self.get_session_from_map(dev_id)
                         rules_to_transfer =  (int(tcam_count) -  int(max_allowed_tcam_entries)) #Calculate the number of TCAM entries to transfer.
                         #rules_to_transfer = 1 #for time being hardcode the number of rules to be transferred to 1.
                         LOG.info('\n Number of TCAM rules/Monitoring agents to transfer %r'%rules_to_transfer)
                         tcam_trnsfd_count = 0 #This is used to track the number of agents that have been moved to some other switch.
                         while(tcam_trnsfd_count < rules_to_transfer):
                             mon_id = self.get_mon_agent_to_transfer(dev_id)  #Used to get the monitoring agent's ID that should be transferred onto some other switch.
                             xml_string = self.create_mon_status_msg(mon_id,dev_id)
                             rpc_reply = self.monitor_status_get(xml_string)
                             rpc_reply_xml = ET.fromstring(rpc_reply.xml)   #Get the XML equivalent of RPC-Reply. It essentially returns a raw string, process it using fromstring function to get XML.
                             LOG.info('\n received monitoring status %s'% rpc_reply)

                             if rpc_reply is not None:
                                stat_packets = self.remove_namespace_get_element_text(rpc_reply_xml,"http://monitoring-automata.net/sdn-mon-automata","stat-packets")   #Get the packet statistics from Mon-status message.
                                stat_bytes =   self.remove_namespace_get_element_text(rpc_reply_xml,"http://monitoring-automata.net/sdn-mon-automata","stat-bytes")     #Get the bytes statistics from Mon-Satus message.

                                mon_status_elem = self.create_monitoring_status_sub_tree(stat_packets,stat_bytes)       #create a monitoring_status subtree to append it to MON_HELLO message.
                                mon_params = node_ele.get_mon_params_frm_mon_agents_map(mon_id)                         #get the monitoring parameters from the mon_agent object of the switch that is currently monitoring this flow  and modify the parameters by adding monitorin_status sub-tree.

                                mon_stop_xml = self.create_mon_stop_msg(mon_id,dev_id)   #Stop the monitoring on this switch.
                                self.monitor_stop(mon_stop_xml)

                                new_mon_params = self.parse_tree_and_update_mon_status(ET.fromstring(mon_params),mon_status_elem)      #Create the monitoring parameters with new monitoring status.
                                LOG.info('\n new monitoring parameters to be sent to the switch %s'%new_mon_params)

                                #This is the interface for switch selection algorithm.
                                new_dev_id = self.get_new_device_to_transfer_the_agent() #At this point it is not sure what needs to be passed to this function. This is the interface for the switch selection algorithm.

                                final_mon_params = self.modify_mon_params_with_new_dev_id(new_mon_params,new_dev_id)
                                LOG.info('\n Final monitoring parameters to be sent to the switch %s'%final_mon_params)

                                xml_string = ET.tostring(final_mon_params)  #conver this into an XML String.

                                LOG.info( "\n\n Newly composed XML Content is \n\n %s "%xml_string)
                                host_name = '192.168.0.105'
                                port_id='830'
                                user='root'
                                pwd='onl'
                                self.monitor_start(xml_string,host_name,port_id,user,pwd)

                             tcam_trnsfd_count = (tcam_trnsfd_count + 1)  #Just increment the counter to keep track of number of agents that were transferred.
        #print 'Time different list:'
        #print self.time_diff
