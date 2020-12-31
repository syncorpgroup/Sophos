#!/usr/bin/env python
"""
Introduction:
    Library to control a Sophos Firewall XG via API.
    The idea here is construct a HTTP GET in XML form-based as mentioned on API Sophos link:
    https://docs.sophos.com/nsg/sophos-firewall/18.0/API/index.html

Usage:
    Declare user, pass and IP to connect a Firewall XG.
    By deault, it use IP Address 172.16.16.16 and port 4444.
    sophosxg('user','pass')

    There are three mayor method group here: GET, SET, DEL.

    set_xxx(arguments) : Method to set information on Firewall XG
    get_xxx()          : Method to obtain information from Firewall XG.
    del_xxx(argument)  : Method to delete information on Firewall XG

Examples:
    from sophoslib import sophosxg

    fw = sophosxg('apiadmin','SYNCORP_Passw0rd')

    fw.set_iphost('Test1','5.5.5.5')
    fw.get_iphost()
    fw.del_iphost('Test1')

For more information in how to activate the API for Sophos XG Firewall, check:
https://support.sophos.com/support/s/article/KB-000038263?language=en_US
"""
import xml.etree.ElementTree as ET
import xmltodict
import copy
import requests
from json import loads, dumps
requests.packages.urllib3.disable_warnings()


__author__ = "Kevin Anel Hernandez Ruiz"
__copyright__ = "Copyleft 2020, The SYNCORP Project."
__credits__ = ["Kevin Anel Hernandez Ruiz"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Kevin Hernandez"
__email__ = "kevin@syncorpgroup.com"
__status__ = "Production"
__GITHUB__ = "https://github.com/kdemenx"
__webpage__ = "https://www.syncorpgroup.com"


class sophosxg(object):
    """
    Parameters
    ----------
    username :  str
                username with API profile permission
    password :  str
                password with API profile permission
    ip       :  str
                IP Address or DNS of Firewall XG. Default: 172.16.16.16
    port     :  str
                TCP Port to connect to Sophos XG. Default: 4444

    Examples:
        fw = sophosxg('apiadmin','SYNCORP_Passw0rd')
        fw = sophosxg('apiadmin','SYNCORP_Passw0rd','192.168.10.1')
        fw = sophosxg('apiadmin','SYNCORP_Passw0rd','192.168.10.1','443')
    """

    def __init__(self, username, password, ip='172.16.16.16', port='4444'):
        self.username = username
        self.password = password
        self.apiurl = 'https://{0}:{1}/webconsole/APIController?reqxml='.format(
            ip, port)
        self.xml_auth = ET.Element('Request')
        xml_login = ET.SubElement(self.xml_auth, 'Login')
        ET.SubElement(xml_login, 'Username').text = self.username
        ET.SubElement(xml_login, 'Password').text = self.password

##########################################################################
# Get subclasses
##########################################################################

    def get_localserviceacl(self):
        self.make_xml('Get', 'LocalServiceACL')
        return self.send()

    def get_adminsettings(self):
        self.make_xml('Get', 'AdminSettings')
        return self.send()

    def get_services(self):
        self.make_xml('Get', 'Services')
        return self.send()

    def get_iphost(self):
        self.make_xml('Get', 'IPHost')
        return self.send()

    def get_iphostgroup(self):
        self.make_xml('Get', 'IPHostGroup')
        return self.send()

    def get_network_interface(self):
        self.make_xml('Get', 'Interface')
        return self.send()

    def get_network_vlan(self):
        self.make_xml('Get', 'VLAN')
        return self.send()

    def get_network_lag(self):
        self.make_xml('Get', 'LAG')
        return self.send()

    def get_network_bridge(self):
        self.make_xml('Get', 'BridgePair')
        return self.send()

    def get_network_zone(self):
        self.make_xml('Get', 'Zone')
        return self.send()

    def get_ips_policy(self):
        self.make_xml('Get', 'IPSPolicy')
        return self.send()

    def get_firewallrule(self):
        self.make_xml('Get', 'FirewallRule')
        return self.send()

    def get_routing_unicast(self):
        self.make_xml('Get', 'UnicastRoute')
        return self.send()

    def get_sys_services(self):
        self.make_xml('Get', 'SystemServices')
        return self.send()

    def get_sys_centralmgmt(self):
        self.make_xml('Get', 'CentralManagement')
        return self.send()

    def get_sys_notification(self):
        self.make_xml('Get', 'Notification')
        return self.send()

    def get_conf_log(self):
        self.make_xml('Get', 'SyslogServers')
        return self.send()

    def get_custom(self,custom):
        self.make_xml('Get', custom)
        return self.send()
##########################################################################
# Set subclasses
##########################################################################

    def set_iphost(self, name, ipaddress, subnet='', hosttype='IP', ipfamily='IPv4'):
        """
        GUI path:
            SYSTEM - Host and Services - IP Host

        Parameters
        ----------
        name            :  str
                            name of object host
        ipaddress       :  str
                            It usages depend of hosttype variable:

                            Hostype   = IP (Default)
                                Value = IP Address

                            Hostype   = Network
                                Value = IP Network.
                                Note: Please keep in mind the CIDR format here.
                                Note: As elaborate of this code (Version 1800.2).
                                Note: There is no verification by Sophos XG for CIDR format via API (GUI does)

                            Hostype   = IP Range
                                Value = Start IP Address
                                Note: This value is usage in conjunction with variable 'subnet' as End IP Address.

                            Hostype   = IP List
                                Value = List Of IP Addresses
                                Note: This is a unique string with all ip address with
                                      NO SPACES, divided by commas (,). See examples.

                            hosttype :  str
                                There are 4 values here:
                                - IP, Network, IPRange, IPList
                                Its values modify ipaddress and subnet variable usages. See more info on variables.

        ipfamily        :  str
                            Declare IP Family: IPv4 or IPv6. Default: IPv4

        ----------
        Examples:
            fw.set_iphost('SYNCORP1','5.5.5.5')
            fw.set_iphost('SYNCORP2','25.25.25.128','255.255.255.128','Network')
            fw.set_iphost('SYNCORP3','192.168.10.10','192.168.10.253','IPRange')
            fw.set_iphost('SYNCORP4','4.4.4.4,5.5.5.5,6.6.6.6',hosttype='IPList')
        """
        xml_child = self.make_xml('Set', 'IPHost')

        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'IPFamily').text = ipfamily
        ET.SubElement(xml_child, 'HostType').text = hosttype

        if hosttype == 'IP':
            ET.SubElement(xml_child, 'IPAddress').text = ipaddress
        elif hosttype == 'Network':
            ET.SubElement(xml_child, 'IPAddress').text = ipaddress
            ET.SubElement(xml_child, 'Subnet').text = subnet
        elif hosttype == 'IPRange':
            ET.SubElement(xml_child, 'StartIPAddress').text = ipaddress
            ET.SubElement(xml_child, 'EndIPAddress').text = subnet
        elif hosttype == 'IPList':
            ET.SubElement(xml_child, 'ListOfIPAddresses').text = ipaddress

#        print(ET.tostring(self.xml_request).decode('utf-8'))
        return self.send()

    def set_iphostgroup(self, name, hosts, description='', ipfamily='IPv4'):
        """
        GUI path:
            SYSTEM - Host and Services - IP Host group

        Parameters
        ----------
        name                :   str
                                name of object host group

        hosts               :   list
                                group different host in Python list. Please make sure that
                                host was made previously by method set_iphost(arguments)

        description         :   str
                                Description in string format.

        ipfamily            :   str
                                Declare IP Family: IPv4 or IPv6. Default: IPv4

        ----------
        Examples:
            fw.set_iphostgroup('GROUP1',['SYNCORP1','SYNCORP2','SYNCORP3'])
            fw.get_iphostgroup()
            fw.del_iphostgroup('GROUP1')
        """
        xml_child = self.make_xml('Set', 'IPHostGroup')
        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'IPFamily').text = ipfamily
        ET.SubElement(xml_child, 'Description').text = description
        xml_child2 = ET.SubElement(xml_child, 'HostList')
        for i in hosts:
            ET.SubElement(xml_child2, 'Host').text = i

#        print(ET.tostring(self.xml_request).decode('utf-8'))
        return self.send()

    def set_network_vlan(self, interface, vlan, zone, ipaddress, netmask, ipv4configuration='Enable', ipv4assignment='Static'):
        """
        GUI path:
            CONFIGURE - Network - Interfaces - VLAN

        Parameters
        ----------
        interface           :   str
                                Name of Physical or Virtual interface to create a VLAN.

        vlan                :   str
                                Vlan value number.

        zone                :   str
                                Security Zone that you want to assign VLAN.

        ipaddress           :   str
                                IP Address to assign subinterface VLAN.

        netmask             :   str
                                Network mask for IP Address variable.

        ipv4configuration   :   str
                                Active IPv4 configuration. Default = 'Enable'.
                                It's required at least one IP Family (IPv4/IPv6)

        ipv4assignment      :   str
                                Only 'Static', 'PPPoe', 'DHCP' are allowed.
                                Default = 'Static'

        ----------
        Examples:
            fw.set_network_vlan('PortD','1004','LAN','1.1.1.3','255.255.255.255')
        """
        xml_child = self.make_xml('Set', 'VLAN')

        ET.SubElement(xml_child, 'Name').text = interface + '.' + vlan
        ET.SubElement(xml_child, 'Hardware').text = interface + '.' + vlan
        ET.SubElement(xml_child, 'Interface').text = interface
        ET.SubElement(xml_child, 'Zone').text = zone
        ET.SubElement(xml_child, 'VLANID').text = vlan
        ET.SubElement(xml_child, 'IPv4Configuration').text = ipv4configuration
        ET.SubElement(xml_child, 'IPv4Assignment').text = ipv4assignment
        ET.SubElement(xml_child, 'IPAddress').text = ipaddress
        ET.SubElement(xml_child, 'Netmask').text = netmask

        return self.send()

    def set_network_lag(self, name, interfaces, zone, ipaddress, netmask,
                        mode='802.3ad(LACP)', ipassignment='Static', ipv4configuration='Enable',
                        xmithashpolicy='Layer2', mtu='1500', mac='Default'):
        """
        GUI path:
            CONFIGURE - Network - Interfaces - LAG

        Parameters
        ----------
        name                :   str
                                Name for LAG Virtual interface.

        interfaces          :   list
                                group different physical interfaces in Python list.

        zone                :   str
                                Security Zone that you want to assign LAG.

        ipaddress           :   str
                                IP Address to assign LAG interface.

        netmask             :   str
                                Network mask for IP Address variable.

        mode                :   str
                                modes available: '802.3ad(LACP)' 'ActiveBackup'
                                Default = '802.3ad(LACP)'

        xmithashpolicy      :   str
                                Load balancing method available:
                                'Layer2', 'Layer2+3', 'Layer3+4'.
                                Default = 'Layer2'

        mtu                 :   str
                                Specify Maximum Transmission Unit(MTU)value.
                                Range 576 to 9000 is allowed.
                                Default = '1500'

        mac                 :   str
                                Select to use default MAC Address.
                                Maximum characters allowed are 17.
                                Default = 'Default'

        ipv4configuration   :   str
                                Active IPv4 configuration. Default = 'Enable'.
                                It's required at least one IP Family (IPv4/IPv6)

        ipv4assignment      :   str
                                Only 'Static', 'DHCP' are allowed.
                                Default = 'Static'

        ----------
        Examples:
            portsgroup= ['PortF','PortG','PortH']
            fw.set_network_lag('LAG1',portsgroup,'LAN','2.1.1.10','255.255.255.255')
            fw.set_network_lag('LAG1',portsgroup,'LAN','2.1.1.10','255.255.255.255',mode='ActiveBackup')
        """
        xml_child = self.make_xml('Set', 'LAG')

        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'Hardware').text = name

        xml_child2 = ET.SubElement(xml_child, 'MemberInterface')
        for i in interfaces:
            ET.SubElement(xml_child2, 'Interface').text = i

        ET.SubElement(xml_child, 'Mode').text = mode
        ET.SubElement(xml_child, 'NetworkZone').text = zone
        ET.SubElement(xml_child, 'IPv4Configuration').text = ipv4configuration
        ET.SubElement(xml_child, 'IPAssignment').text = ipassignment
        ET.SubElement(xml_child, 'IPv4Address').text = ipaddress
        ET.SubElement(xml_child, 'Netmask').text = netmask
        ET.SubElement(xml_child, 'MTU').text = mtu
        ET.SubElement(xml_child, 'MACAddress').text = mac
        if mode == '802.3ad(LACP)':
            ET.SubElement(xml_child, 'XmitHashPolicy').text = xmithashpolicy
#        ET.SubElement(xml_child,'InterfaceSpeed').text    = 'Auto Negotiate'
#        xml_child2= ET.SubElement(xml_child,'MSS')
#        ET.SubElement(xml_child2,'OverrideMSS').text      = 'Enable'
#        ET.SubElement(xml_child2,'MSSValue').text         = '1460'

        return self.send()

    def set_network_bridge(self, name, interfaces, ipaddress='', netmask='', gw='',
                           routingonbridge='Disable', ipassignment='Static',
                           ipv4configuration='Enable', mtu='1500'):
        """
        GUI path:
            CONFIGURE - Network - Interfaces - Bridge

        Parameters
        ----------
        name                :   str
                                Name for Bridge Virtual interface.

        interfaces          :   dict
                                group different physical or Virtual interfaces in Python dictionary.
                                It require at least 2 Interfaces/Zone.
                                Keys   dictionary represent Port.
                                Values dictionary represent Zone.
                                Example: ['PortA': 'LAN', 'PortB': 'WAN']

        routingonbridge     :   str
                                Used to enable routing on bridge-pair.
                                Default = 'Disable'

        ipaddress           :   str (Optional)
                                IP Address to assign Bridge interface.
                                Default = ''

        netmask             :   str (Optional)
                                Network mask for IP Address variable.
                                Default = ''

        gw                  :   str (Optional)
                                Specify Gateway IP Address for IPv4 Configuration.
                                Default = ''

        mtu                 :   str
                                Specify Maximum Transmission Unit(MTU)value.
                                Range 576 to 9000 is allowed.
                                Default = '1500'

        ipv4configuration   :   str
                                Active IPv4 configuration. Default = 'Enable'.
                                It's required at least one IP Family (IPv4/IPv6)

        ipv4assignment      :   str
                                Only 'Static', 'DHCP' are allowed.
                                Default = 'Static'

        ----------
        Examples:
            bridge1={ 'PortG': 'LAN', 'PortH': 'WAN' }
            bridge2={ 'PortE': 'DMZ', 'PortF': 'LAN' }
            fw.set_network_bridge('Bridge100',bridge1,'3.3.3.3','255.255.255.0','3.3.3.1')
            fw.set_network_bridge('Bridge101',bridge2)
        """
        xml_child = self.make_xml('Set', 'BridgePair')

        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'Hardware').text = name
        ET.SubElement(xml_child, 'Description').text = str(
            len(interfaces.keys())) + ' Bridges'
        ET.SubElement(xml_child, 'RoutingOnBridgePair').text = routingonbridge

        xml_child2 = ET.SubElement(xml_child, 'BridgeMembers')
        for x, y in interfaces.items():
            xml_child3 = ET.SubElement(xml_child2, 'Member')
            ET.SubElement(xml_child3, 'Interface').text = x
            ET.SubElement(xml_child3, 'Zone').text = y

        if ipaddress and netmask and gw:
            ET.SubElement(
                xml_child, 'IPv4Configuration').text = ipv4configuration
            ET.SubElement(xml_child, 'IPv4Assignment').text = ipassignment
            ET.SubElement(xml_child, 'IPAddress').text = ipaddress
            ET.SubElement(xml_child, 'Netmask').text = netmask
            xml_child2 = ET.SubElement(xml_child, 'Gateway')
            ET.SubElement(xml_child2, 'GatewayName').text = 'GW for ' + name
            ET.SubElement(xml_child2, 'GatewayIPAddress').text = gw

        ET.SubElement(xml_child, 'MTU').text = mtu
#        xml_child2= ET.SubElement(xml_child,'MSS')
#        ET.SubElement(xml_child2,'Override').text         = 'Enable'
#        ET.SubElement(xml_child2,'MSSValue').text         = '1460'

#        print(ET.tostring(self.xml_request).decode('utf-8'))
        return self.send()

    def set_network_zone(self, zone, description, type='LAN', https='Disable', ssh='Disable',
                         clientauth='Disable', captiveportal='Disable', ntlm='Disable', radiussso='Disable',
                         dns='Disable', ping='Disable', webproxy='Disable', sslvpn='Disable',
                         userportal='Disable', dynamicrouting='Disable', smtprelay='Disable', snmp='Disable'):
        """
        GUI path:
            CONFIGURE - Network - Interfaces - Bridge

        Parameters
        ----------
        zone                :   str
                                Name of Zone.

        description         :   str
                                Description in string format.

        type                :   str
                                Select the type of Zone from the available options: LAN or DMZ.
                                Only 'LAN', 'WAN', 'DMZ', 'LOCAL', 'VPN', 'Discover' are allowed.
                                Default = 'LAN'

        https, ssh,
        clientauth,
        captiveportal,
        ntlm, radiussso,
        dns, ping, webproxy,
        sslvpn, userportal,
        dynamicrouting,
        smtprelay, snmp     :   str
                                Define the type of administrative access permitted on zone.
                                Default = 'Disable'

        ----------
        Examples:
            fw.set_network_zone('SYNCORP','The best security zone ever.')
        """
        xml_child = self.make_xml('Set', 'Zone')

        ET.SubElement(xml_child, 'Name').text = zone
        ET.SubElement(xml_child, 'Type').text = type
        ET.SubElement(xml_child, 'Description').text = description

        xml_child2 = ET.SubElement(xml_child, 'ApplianceAccess')

        xml_child3 = ET.SubElement(xml_child2, 'AdminServices')
        ET.SubElement(xml_child3, 'HTTPS').text = https
        ET.SubElement(xml_child3, 'SSH').text = ssh

        xml_child3 = ET.SubElement(xml_child2, 'AuthenticationServices')
        ET.SubElement(xml_child3, 'ClientAuthentication').text = clientauth
        ET.SubElement(xml_child3, 'CaptivePortal').text = captiveportal
        ET.SubElement(xml_child3, 'NTLM').text = ntlm
        ET.SubElement(xml_child3, 'RadiusSSO').text = radiussso

        xml_child3 = ET.SubElement(xml_child2, 'NetworkServices')
        ET.SubElement(xml_child3, 'DNS').text = dns
        ET.SubElement(xml_child3, 'Ping').text = ping

        xml_child3 = ET.SubElement(xml_child2, 'OtherServices')
        ET.SubElement(xml_child3, 'WebProxy').text = webproxy
        ET.SubElement(xml_child3, 'SSLVPN').text = sslvpn
        ET.SubElement(xml_child3, 'UserPortal').text = userportal
        ET.SubElement(xml_child3, 'DynamicRouting').text = dynamicrouting
        ET.SubElement(xml_child3, 'SMTPRelay').text = smtprelay
        ET.SubElement(xml_child3, 'SNMP').text = snmp

        return self.send()

    def set_ips_policy(self, name, template, description=''):
        xml_child = self.make_xml('Set', 'IPSPolicy')

        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'Template').text = template
        ET.SubElement(xml_child, 'Description').text = description

        return self.send()

    def set_firewallrule(self, name, action, description='', status='Enable',
                         srczones='', srcnet='', dstzones='', dstnet='', services='', schedule='All The Time',
                         ipfamily='IPv4', position='top', logtraffic='Enable', skiplocaldest='Disable',
                         matchidentity='', captiveportal='Enable', member='', dataaccounting='Disable',
                         webfilter='None', webqos='Revoke', blockquic='Disable', scanvirus='Enable', sandstorm='Enable',
                         scanftp='Disable', proxymode='Disable', decrypthttps='Disable',
                         srcheartbeat='Disable', dstheartbeat='Disable',
                         appcontrol='None', appqos='Revoke',
                         ips='None', shapeqos='None',
                         scansmtp='Disable', scansmtps='Disable', scanimap='Disable',
                         scanimaps='Disable', scanpop3='Disable', scanpop3s='Disable'):
        xml_child = self.make_xml('Set', 'FirewallRule')

        ET.SubElement(xml_child, 'Name').text = name
        ET.SubElement(xml_child, 'Description').text = description
        ET.SubElement(xml_child, 'Status').text = status
        ET.SubElement(xml_child, 'IPFamily').text = ipfamily
        ET.SubElement(xml_child, 'Position').text = position

        if matchidentity:
            ET.SubElement(xml_child, 'PolicyType').text = 'User'
            xml_child2 = ET.SubElement(xml_child, 'UserPolicy')
        else:
            ET.SubElement(xml_child, 'PolicyType').text = 'Network'
            xml_child2 = ET.SubElement(xml_child, 'NetworkPolicy')

        ET.SubElement(xml_child2, 'Action').text = action
        ET.SubElement(xml_child2, 'LogTraffic').text = logtraffic
        ET.SubElement(xml_child2, 'SkipLocalDestined').text = skiplocaldest

        xml_child3 = ET.SubElement(xml_child2, 'SourceZones')
        for i in srczones:
            ET.SubElement(xml_child3, 'Zone').text = i

        xml_child3 = ET.SubElement(xml_child2, 'SourceNetworks')
        for i in srcnet:
            ET.SubElement(xml_child3, 'Network').text = i

        xml_child3 = ET.SubElement(xml_child2, 'Services')
        for i in services:
            ET.SubElement(xml_child3, 'Service').text = i

        ET.SubElement(xml_child2, 'Schedule').text = schedule

        xml_child3 = ET.SubElement(xml_child2, 'DestinationZones')
        for i in dstzones:
            ET.SubElement(xml_child3, 'Zone').text = i

        xml_child3 = ET.SubElement(xml_child2, 'DestinationNetworks')
        for i in dstnet:
            ET.SubElement(xml_child3, 'Network').text = i

        if matchidentity:
            ET.SubElement(xml_child2, 'MatchIdentity').text = matchidentity
            ET.SubElement(xml_child2, 'ShowCaptivePortal').text = captiveportal
            xml_child3 = ET.SubElement(xml_child2, 'Identity')
            for i in member:
                ET.SubElement(xml_child3, 'Member').text = i
            ET.SubElement(xml_child2, 'DataAccounting').text = dataaccounting

        ET.SubElement(xml_child2, 'WebFilter').text = webfilter
        ET.SubElement(xml_child2, 'WebCategoryBaseQoSPolicy').text = webqos
        ET.SubElement(xml_child2, 'BlockQuickQuic').text = blockquic
        ET.SubElement(xml_child2, 'ScanVirus').text = scanvirus
        ET.SubElement(xml_child2, 'Sandstorm').text = sandstorm
        ET.SubElement(xml_child2, 'ScanFTP').text = scanftp
        ET.SubElement(xml_child2, 'ProxyMode').text = proxymode
        ET.SubElement(xml_child2, 'DecryptHTTPS').text = decrypthttps
        ET.SubElement(
            xml_child2, 'SourceSecurityHeartbeat').text = srcheartbeat
        ET.SubElement(xml_child2, 'DestSecurityHeartbeat').text = dstheartbeat
        ET.SubElement(xml_child2, 'ApplicationControl').text = appcontrol
        ET.SubElement(xml_child2, 'ApplicationBaseQoSPolicy').text = appqos
        ET.SubElement(xml_child2, 'IntrusionPrevention').text = ips
        ET.SubElement(xml_child2, 'TrafficShapingPolicy').text = shapeqos
        ET.SubElement(xml_child2, 'ScanSMTP').text = scansmtp
        ET.SubElement(xml_child2, 'ScanSMTPS').text = scansmtps
        ET.SubElement(xml_child2, 'ScanIMAP').text = scanimap
        ET.SubElement(xml_child2, 'ScanIMAPS').text = scanimaps
        ET.SubElement(xml_child2, 'ScanPOP3').text = scanpop3
        ET.SubElement(xml_child2, 'ScanPOP3S').text = scanpop3s

#        print(ET.tostring(self.xml_request).decode('utf-8'))
        return self.send()

##########################################################################
# Remove subclasses
##########################################################################
    def del_iphost(self, name):
        xml_child = self.make_xml('Remove', 'IPHost')
        ET.SubElement(xml_child, 'Name').text = name
        return self.send()

    def del_iphostgroup(self, name):
        xml_child = self.make_xml('Remove', 'IPHostGroup')
        ET.SubElement(xml_child, 'Name').text = name
        return self.send()

    def del_network_vlan(self, hardware):
        xml_child = self.make_xml('Remove', 'VLAN')
        ET.SubElement(xml_child, 'Hardware').text = hardware
        return self.send()

    def del_network_lag(self, hardware):
        xml_child = self.make_xml('Remove', 'LAG')
        ET.SubElement(xml_child, 'Hardware').text = hardware
        return self.send()

    def del_network_bridge(self, hardware):
        xml_child = self.make_xml('Remove', 'BridgePair')
        ET.SubElement(xml_child, 'Hardware').text = hardware
        return self.send()

    def del_network_zone(self, name):
        xml_child = self.make_xml('Remove', 'Zone')
        ET.SubElement(xml_child, 'Name').text = name
        return self.send()

    def del_ips_policy(self, name):
        xml_child = self.make_xml('Remove', 'IPSPolicy')
        ET.SubElement(xml_child, 'Name').text = name
        return self.send()

    def del_firewallrule(self, name):
        xml_child = self.make_xml('Remove', 'FirewallRule')
        ET.SubElement(xml_child, 'Name').text = name
        return self.send()
##########################################################################
# defining xml and send subclasses
##########################################################################

    def make_xml(self, method, module):
        self.method = method
        self.module = module
        self.xml_request = copy.deepcopy(self.xml_auth)
        xml_method = ET.SubElement(self.xml_request, method)
        xml_child = ET.SubElement(xml_method, module)
        return xml_child

    def send(self):

        str_xml_request = ET.tostring(self.xml_request).decode('utf-8')

        response = requests.get(self.apiurl + str_xml_request, verify=False)
        response_dict = loads(dumps( xmltodict.parse(response.content) ))

        if not response_dict['Response']['Login']['status'] == "Authentication Successful":
            raise Exception(response_dict['Response']['Login']['status'])

        if ((self.method == 'Remove' or self.method == 'Set') and
                not response_dict['Response'][self.module]['Status']['@code'] == "200"):
            raise Exception(response_dict['Response'][self.module]['Status']['@code'],
                            response_dict['Response'][self.module]['Status']['#text'])

        return response_dict if self.method == 'Get' else response_dict['Response'][self.module]['Status']['@code'] + ' ' + response_dict['Response'][self.module]['Status']['#text']

##########################################################################
