import struct
# http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml

# decode DHCP / BOOTP messages

class DHCPPacket:
    optionnames= {
  0:"Pad", # None
  1:"SubnetMask", # Subnet Mask Value
  2:"TimeOffset", # Time Offset in Seconds from UTC (note: deprecated by 100 and 101)
  3:"Router", # N/4 Router addresses
  4:"TimeServer", # N/4 Timeserver addresses
  5:"NameServer", # N/4 IEN-116 Server addresses
  6:"DomainServer", # N/4 DNS Server addresses
  7:"LogServer", # N/4 Logging Server addresses
  8:"QuotesServer", # N/4 Quotes Server addresses
  9:"LPRServer", # N/4 Printer Server addresses
 10:"ImpressServer", # N/4 Impress Server addresses
 11:"RLPServer", # N/4 RLP Server addresses
 12:"Hostname", # Hostname string
 13:"BootFileSize", # Size of boot file in 512 byte chunks
 14:"MeritDumpFile", # Client to dump and name the file to dump it to
 15:"DomainName", # The DNS domain name of the client
 16:"SwapServer", # Swap Server address
 17:"RootPath", # Path name for root disk
 18:"ExtensionFile", # Path name for more BOOTP info
 19:"ForwardOn/Off", # Enable/Disable IP Forwarding
 20:"SrcRteOn/Off", # Enable/Disable Source Routing
 21:"PolicyFilter", # Routing Policy Filters
 22:"MaxDGAssembly", # Max Datagram Reassembly Size
 23:"DefaultIPTTL", # Default IP Time to Live
 24:"MTUTimeout", # Path MTU Aging Timeout
 25:"MTUPlateau", # Path MTU Plateau Table
 26:"MTUInterface", # Interface MTU Size
 27:"MTUSubnet", # All Subnets are Local
 28:"BroadcastAddress", # Broadcast Address
 29:"MaskDiscovery", # Perform Mask Discovery
 30:"MaskSupplier", # Provide Mask to Others
 31:"RouterDiscovery", # Perform Router Discovery
 32:"RouterRequest", # Router Solicitation Address
 33:"StaticRoute", # Static Routing Table
 34:"Trailers", # Trailer Encapsulation
 35:"ARPTimeout", # ARP Cache Timeout
 36:"Ethernet", # Ethernet Encapsulation
 37:"DefaultTCPTTL", # Default TCP Time to Live
 38:"KeepaliveTime", # TCP Keepalive Interval
 39:"KeepaliveData", # TCP Keepalive Garbage
 40:"NISDomain", # NIS Domain Name
 41:"NISServers", # NIS Server Addresses
 42:"NTPServers", # NTP Server Addresses
 43:"VendorSpecific", # Vendor Specific Information
 44:"NETBIOSNameSrv", # NETBIOS Name Servers
 45:"NETBIOSDistSrv", # NETBIOS Datagram Distribution
 46:"NETBIOSNodeType", # NETBIOS Node Type
 47:"NETBIOSScope", # NETBIOS Scope
 48:"XWindowFont", # X Window Font Server
 49:"XWindowManager", # X Window Display Manager
 50:"AddressRequest", # Requested IP Address
 51:"AddressTime", # IP Address Lease Time
 52:"Overload", # Overload "sname" or "file"
 53:"DHCPMsgType", # DHCP Message Type
 54:"DHCPServerId", # DHCP Server Identification
 55:"ParameterList", # Parameter Request List
 56:"DHCPMessage", # DHCP Error Message
 57:"DHCPMaxMsgSize", # DHCP Maximum Message Size
 58:"RenewalTime", # DHCP Renewal (T1) Time
 59:"RebindingTime", # DHCP Rebinding (T2) Time
 60:"ClassId", # Class Identifier
 61:"ClientId", # Client Identifier
 62:"NetWare/IPDomain", # NetWare/IP Domain Name
 63:"NetWare/IPOption", # NetWare/IP sub Options
 64:"NIS-Domain-Name", # NIS+ v3 Client Domain Name
 65:"NIS-Server-Addr", # NIS+ v3 Server Addresses
 66:"Server-Name", # TFTP Server Name
 67:"Bootfile-Name", # Boot File Name
 68:"Home-Agent-Addrs", # Home Agent Addresses
 69:"SMTP-Server", # Simple Mail Server Addresses
 70:"POP3-Server", # Post Office Server Addresses
 71:"NNTP-Server", # Network News Server Addresses
 72:"WWW-Server", # WWW Server Addresses
 73:"Finger-Server", # Finger Server Addresses
 74:"IRC-Server", # Chat Server Addresses
 75:"StreetTalk-Server", # StreetTalk Server Addresses
 76:"STDA-Server", # ST Directory Assist. Addresses
 77:"User-Class", # User Class Information
 78:"DirectoryAgent", # directory agent information
 79:"ServiceScope", # service location agent scope
 80:"RapidCommit", # Rapid Commit
 81:"ClientFQDN", # Fully Qualified Domain Name
 82:"RelayAgentInformation", # Relay Agent Information
 83:"iSNS", # Internet Storage Name Service
# 84:"REMOVED/Unassigned", # 
 85:"NDSServers", # Novell Directory Services
 86:"NDSTreeName", # Novell Directory Services
 87:"NDSContext", # Novell Directory Services
 88:"BCMCSControllerDomainNamelist", # 
 89:"BCMCSControllerIPv4addressoption", # 
 90:"Authentication", # Authentication
 91:"client-last-transaction-timeoption", # 
 92:"associated-ipoption", # 
 93:"ClientSystem", # Client System Architecture
 94:"ClientNDI", # Client Network Device Interface
 95:"LDAP", # Lightweight Directory Access Protocol
 96:"REMOVED/Unassigned", # 
 97:"UUID/GUID", # UUID/GUID-based Client Identifier
 98:"User-Auth", # Open Group's User Authentication
 99:"GEOCONF_CIVIC", # 
100:"PCode", # IEEE 1003.1 TZ String
101:"TCode", # Reference to the TZ Database
102:"REMOVED/Unassigned", # 
108:"REMOVED/Unassigned", # 
109:"Unassigned", # 
110:"REMOVED/Unassigned", # 
111:"Unassigned", # 
112:"NetinfoAddress", # NetInfo Parent Server Address
113:"NetinfoTag", # NetInfo Parent Server Tag
114:"URL", # URL
115:"REMOVED/Unassigned", # 
116:"Auto-Config", # DHCP Auto-Configuration
117:"NameServiceSearch", # Name Service Search
118:"SubnetSelectionOption", # Subnet Selection Option
119:"DomainSearch", # DNS domain search list
120:"SIPServersDHCPOption", # SIP Servers DHCP Option
121:"ClasslessStaticRouteOption", # Classless Static Route Option
122:"CCC", # CableLabs Client Configuration
123:"GeoConfOption", # GeoConf Option
124:"V-IVendorClass", # Vendor-Identifying Vendor Class
125:"V-IVendor-SpecificInformation", # Vendor-Identifying Vendor-Specific Information
126:"Removed/Unassigned", # 
127:"Removed/Unassigned", # 
128:"PXE-undefined(vendorspecific)", # 
128:"Etherbootsignature.6bytes:E4:45:74:68:00:00", # 
128:"DOCSISserverIPaddress",
128:"TFTPServerIPaddress(forIPPhonesoftwareload)", # 
129:"PXE-undefined(vendorspecific)", # 
129:"Kerneloptions.Variablelengthstring", # 
129:"CallServerIPaddress", # 
130:"PXE-undefined(vendorspecific)", # 
130:"Ethernetinterface.Variablelengthstring.", # 
130:"Discriminationstring(toidentifyvendor)", # 
131:"PXE-undefined(vendorspecific)", # 
131:"RemotestatisticsserverIPaddress", # 
132:"PXE-undefined(vendorspecific)", # 
132:"IEEE802.1QVLANID", # 
133:"PXE-undefined(vendorspecific)", # 
133:"IEEE802.1D/pLayer2Priority", # 
134:"PXE-undefined(vendorspecific)", # 
134:"DiffservCodePoint(DSCP)forVoIPsignallingandmediastreams", # 
135:"PXE-undefined(vendorspecific)", # 
135:"HTTPProxyforphone-specificapplications", # 
136:"OPTION_PANA_AGENT", # 
137:"OPTION_V4_LOST", # 
138:"OPTION_CAPWAP_AC_V4", # CAPWAP Access Controller addresses
139:"OPTION-IPv4_Address-MoS", # a series of suboptions
140:"OPTION-IPv4_FQDN-MoS", # a series of suboptions
141:"SIPUAConfigurationServiceDomains", # List of domain names to search for SIP User Agent Configuration
142:"OPTION-IPv4_Address-ANDSF", # ANDSF IPv4 Address Option for DHCPv4
143:"Unassigned", # 
144:"GeoLoc", # Geospatial Location with Uncertainty
145:"FORCERENEW_NONCE_CAPABLE", # Forcerenew Nonce Capable
146:"RDNSSSelection", # Information for selecting RDNSS
147:"Unassigned", # 
150:"TFTPserveraddress", # 
150:"Etherboot", # 
150:"GRUBconfigurationpathname", # 
151:"status-code", # Status code and optional N byte text message describing status.
152:"base-time", # Absolute time (seconds since Jan 1, 1970) message was sent.
153:"start-time-of-state", # Number of seconds in the past when client entered current state.
154:"query-start-time", # Absolute time (seconds since Jan 1, 1970) for beginning of query.
155:"query-end-time", # Absolute time (seconds since Jan 1, 1970) for end of query.
156:"dhcp-state", # State of IP address.
157:"data-source", # Indicates information came from local or remote server.
158:"OPTION_V4_PCP_SERVER", # Includes one or multiple lists of PCP server IP addresses; each list is treated as a separate PCP server.
159:"OPTION_V4_PORTPARAMS", # This option is used to configure a set of ports bound to a shared IPv4 address.
160:"DHCPCaptive-Portal", # DHCP Captive-Portal
161:"Unassigned", # 
175:"Etherboot(TentativelyAssigned-2005-06-23)", # 
176:"IPTelephone(TentativelyAssigned-2005-06-23)", # 
177:"Etherboot(TentativelyAssigned-2005-06-23)", # 
177:"PacketCableandCableHome(replacedby122)", # 
178:"Unassigned", # 
208:"PXELINUXMagic", # magic string = F1:00:74:7E
209:"ConfigurationFile", # Configuration file
210:"PathPrefix", # Path Prefix Option
211:"RebootTime", # Reboot Time
212:"OPTION_6RD", # OPTION_6RD with N/4 6rd BR addresses
213:"OPTION_V4_ACCESS_DOMAIN", # Access Network Domain Name
214:"Unassigned", # 
220:"SubnetAllocationOption", # Subnet Allocation Option
221:"VirtualSubnetSelection(VSS)Option", # 
222:"Unassigned", # 
224:"Reserved(PrivateUse)", # 
255:"End", # None
    }
    messagetypenames= {
  1:"DHCPDISCOVER", # [RFC2132]
  2:"DHCPOFFER", # [RFC2132]
  3:"DHCPREQUEST", # [RFC2132]
  4:"DHCPDECLINE", # [RFC2132]
  5:"DHCPACK", # [RFC2132]
  6:"DHCPNAK", # [RFC2132]
  7:"DHCPRELEASE", # [RFC2132]
  8:"DHCPINFORM", # [RFC2132]
  9:"DHCPFORCERENEW", # [RFC3203]
 10:"DHCPLEASEQUERY", # [RFC4388]
 11:"DHCPLEASEUNASSIGNED", # [RFC4388]
 12:"DHCPLEASEUNKNOWN", # [RFC4388]
 13:"DHCPLEASEACTIVE", # [RFC4388]
 14:"DHCPBULKLEASEQUERY", # [RFC6926]
 15:"DHCPLEASEQUERYDONE", # [RFC6926]
 16:"DHCPACTIVELEASEQUERY", # [RFC-ietf-dhc-dhcpv4-active-leasequery-07]
 17:"DHCPLEASEQUERYSTATUS", # [RFC-ietf-dhc-dhcpv4-active-leasequery-07]
 18:"DHCPTLS", # [RFC-ietf-dhc-dhcpv4-active-leasequery-07]
    }

    @staticmethod
    def optionname(code):
        if code in DHCPPacket.optionnames:
            return DHCPPacket.optionnames[code]
        return "opt:"+str(code)
    @staticmethod
    def messagename(code):
        if code in DHCPPacket.messagetypenames:
            return DHCPPacket.messagetypenames[code]
        return "msg:"+str(code)
    class DHCPOption:
        def __init__(self, code, data):
            self.code= code
            self.data= data
        def __str__(self):
            if self.code in (12,15,40,60,62,64,66,67,81,83,86):
                enc= "'"+self.data+"'"
            else:
                enc= self.data.encode("hex")
            return DHCPPacket.optionname(self.code)+":"+enc
    @staticmethod
    def parse(pkt, ofs, last):
        dhcp= DHCPPacket()
        if last-ofs<236:
            print("short dhcp packet")
            return
        dhcp.op, dhcp.htype, dhcp.hlen, dhcp.hops, dhcp.xid, dhcp.secs, dhcp.flags, \
            dhcp.ciaddr, dhcp.yiaddr, dhcp.siaddr, dhcp.giaddr, dhcp.chaddr, dhcp.sname, dhcp.file \
                = struct.unpack_from(">BBBBLHH4s4s4s4s16s64s128s", pkt)

        magic_cookie, = struct.unpack_from(">L", pkt, 236)
        if magic_cookie==0x63825363:
            dhcp.options= DHCPPacket.parse_options(pkt, 240, last)
        else:
            options= None
            print("bootp")

        # op: 1=req, 2=reply
        # htype: hardware type: 1=10mb ether
        # hlen: hardware addr len ( 6 for ether )
        # hops:  incremented by relay agents
        # xid: random nr
        # secs: since start of renewal
        # flags:   bit0 = Broadcast flag
        # ciaddr:  client ip addr
        # yiaddr:  your ip
        # siaddr:  next server
        # giaddr:  relay agent
        # chaddr: client hardware addr
        # sname: server name
        # file:  boot file name


        return dhcp, ofs

    @staticmethod
    def parse_options(pkt, ofs, last):
        opts= []
        while ofs<last:
            code= ord(pkt[ofs])
            ofs += 1
            if code==0 or code==255:
                len= 0
            else:
                len= ord(pkt[ofs])
                ofs += 1
            opts.append(DHCPPacket.DHCPOption(code, pkt[ofs:ofs+len]))
            ofs += len
        return opts

    def __str__(dhcp):
        def stripzeros(x):
            return x.rstrip("\x00")
        r= "%d %d %d %d %08x %d %d" % (dhcp.op, dhcp.htype, dhcp.hlen, dhcp.hops, dhcp.xid, dhcp.secs, dhcp.flags)
        r += " ci="+dhcp.ciaddr.encode("hex")
        r += " yi="+dhcp.yiaddr.encode("hex")
        r += " si="+dhcp.siaddr.encode("hex")
        r += " gi="+dhcp.giaddr.encode("hex")
        r += " ch="+stripzeros(dhcp.chaddr).encode("hex")
        r += " sn="+stripzeros(dhcp.sname).encode("hex")
        r += " fl="+stripzeros(dhcp.file).encode("hex")
        r += "\n"
        r += "\n    ".join(str(x) for x in dhcp.options)
        r += "\n"

        return r

toplevel=DHCPPacket
