import urlparse
import re
import ssl
import json
import socket
import struct
import logging
import urllib2
import hashlib


class FritzBox:
    def __init__(self, logger=None):
        self.services = {}  # type: {}
        self.recursion_cnt = 0
        self.time_out = 3
        self.realm = str()
        self.nonce = str()
        self.auth = str()
        self.ip = str()
        self.port = str()
        self.protocol = str()
        self.location_path = str()
        self.user = str()
        self.password = str()

        if logger is None:
            logging.basicConfig(
                level=logging.DEBUG,                 # Set the logging level to DEBUG
                format='%(asctime)s - %(levelname)s - %(message)s',  # Set the format of log messages
                datefmt='%Y-%m-%d %H:%M:%S'          # Set the format of the date/time in log messages
            )
            self.logger = logging.getLogger()
        else:
            self.logger = logger

    def __str__(self):
        return "{}://{}:{}".format(self.protocol, self.ip, self.port)

    def discover(self, host_ip):
        """
        Uses SSDP to discover FritzBox connection data.
        :return: IP of FritzBox
        :rtype: string
        """
        self.logger.debug("Entering discover(host_ip={})".format(host_ip))

        # SSDP request msg from application
        MCAST_MSG = ('M-SEARCH * HTTP/1.1\r\n' +
                     'HOST: 239.255.255.250:1900\r\n' +
                     'MAN: "ssdp:discover"\r\n' +
                     'MX: 5\r\n' +
                     'ST: urn:dslforum-org:device:InternetGatewayDevice:1\r\n')

        MCAST_GRP = '239.255.255.250'
        MCAST_PORT = 1900

        # for address in self.interface_addresses():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        # time to life for multicast msg
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        # specify interface to use for multicast msg
        sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host_ip))
        sock.settimeout(self.time_out)

        try:
            sock.sendto(MCAST_MSG, (MCAST_GRP, MCAST_PORT))
        except socket.error as e:
            sock.close()
            raise Exception("fritz.py | discover | socket.error {} ".format(e))

        while True:
            try:
                data = str(sock.recv(1024))

                # Search for the Location URL
                location_match = re.search(r'Location:\s*(http://[^\s]+)', data, re.IGNORECASE | re.MULTILINE)
                server_match = re.search(r'Server:\s*.*FRITZ!Box.*', data, re.IGNORECASE | re.MULTILINE)

                # Check if both the Location URL is found and Server contains "FRITZ!Box"
                if location_match is None or server_match is None:
                    continue

                location_url = location_match.group(1)
                self.logger.debug("fritz.py | discover | Found FritzBox location url as {}".format(location_url))

                url_parsed = urlparse.urlparse(location_url)
                if url_parsed is None:
                    continue
                self.ip = url_parsed.hostname
                self.port = url_parsed.port
                self.location_path = url_parsed.path
                self.protocol = url_parsed.scheme
                break

            except socket.timeout:
                raise Exception( "fritz.py | discover | Socket timed out while discovering FritzBox. "
                                 "Functionality of module not available!")

        sock.close()

        # Fetching infor about available services
        self._get_box_services()

        # Get security port
        service_name = "urn:dslforum-org:service:DeviceInfo:1"
        action = "GetSecurityPort"
        attr_list = {}
        data = self.set_soap_action( service_name, action, attr_list)

        if "NewSecurityPort" in data:
            self.port = data["NewSecurityPort"]
            self.protocol = "https"

        self.logger.debug("fritz.py | discover | FritzBox at {}://{}:{}".format(self.protocol, self.ip, self.port))

        return self.ip

    def _fetch_from_url(self, url):
        """
        Simply fetches the response when opening the url
        :param url:
        :return:
        """
        # self.logger.debug("fritz.py | Entering _fetch_from_url({})".format(url))
        url_parsed = urlparse.urlparse(url)

        # Build a SSL Context to disable certificate verification.
        ctx = ssl._create_unverified_context()
        response_data = ""

        try:
            # Build a http request and overwrite host header with the original hostname.
            request = urllib2.Request(url, headers={'Host': url_parsed.hostname})
            # Open the URL and read the response.
            response = urllib2.urlopen(request, timeout=self.time_out, context=ctx)
            response_data = response.read()
        except Exception as e:
            self.logger.exception("fritz.py | _fetch_from_url | Exception: " + str(e))
        return response_data

    def _get_box_services(self):
        location_xml = self._fetch_from_url("{}://{}:{}{}".format(self.protocol,
                                                                   self.ip,
                                                                   self.port,
                                                                   self.location_path))

        service_lists = re.findall(r"<serviceList>(.*?)</serviceList>", location_xml, re.S)
        if len(service_lists) == 0:
            raise Exception("fritz.py | _get_box_services | Could not extract serviceList XML data. Aborting")

        self.services = {}
        for service_list_xml in service_lists:
            service_list = re.findall(r"<service>(.*?)</service>", service_list_xml, re.S)

            for service in service_list:
                service_type = re.search(r'<serviceType>(.*?)</serviceType>', service, flags=re.S)
                service_id = re.search(r'<serviceId>(.*?)</serviceId>', service, flags=re.S)
                control_url = re.search(r'<controlURL>(.*?)</controlURL>', service, flags=re.S)
                event_sub_url = re.search(r'<eventSubURL>(.*?)</eventSubURL>', service, flags=re.S)
                scpd_url = re.search(r'<SCPDURL>(.*?)</SCPDURL>', service, flags=re.S)

                if service_type is None or service_id is None or control_url is None or event_sub_url is None or scpd_url is None:
                    raise Exception("fritz.py | _get_box_services | Required keys not included.")

                service_data =  {"serviceType": service_type.group(1),
                                 "serviceId": service_id.group(1),
                                 "controlURL": control_url.group(1),
                                 "eventSubURL": event_sub_url.group(1),
                                 "SCPDURL": scpd_url.group(1)}

                self.services[service_type.group(1)] = service_data

            self.logger.debug("fritz.py | _get_box_services | self.services.keys = {}".format(self.services.keys()))

    def _get_soap_header(self):
        """
        Generates header data for a soap request.

        :return: Header for SOAP Request
        :rtype: str
        """
        if self.auth == "":
            header = ('<s:Header>\n'
                      '\t<h:InitChallenge xmlns:h="http://soap-authentication.org/digest/2001/10/" '
                      's:mustUnderstand="1">\n'
                      '\t\t<UserID>{}</UserID>\n'
                      '\t</h:InitChallenge >\n'
                      '</s:Header>'.format(self.user))

        else:
            header = ('<s:Header>\n'
                      '\t<h:ClientAuth xmlns:h="http://soap-authentication.org/digest/2001/10/" '
                      's:mustUnderstand="1">\n'
                      '\t\t<Nonce>' + self.nonce + '</Nonce>\n'
                      '\t\t<Auth>' + self.auth + '</Auth>\n'
                      '\t\t<UserID>' + self.user + '</UserID>\n'
                      '\t\t<Realm>' + self.realm + '</Realm>\n'
                      '\t</h:ClientAuth>'
                      '\n</s:Header>')

        return header

    def _get_soap_req(self, service_name, action, attr_list):
        """

        :param service_data:
        :type service_data: {'controlURL': ..., 'serviceType': ...}
        :param action:
        :type action: str
        :param attr_list:
        :type attr_list: []
        :return:
        :rtype: urllib2.Request
        """

        if not service_name in self.services:
            raise Exception("fritz.py | _get_soap_req | Service {} is unknown ".format(service_name))
        else:
            self.logger.debug("fritz.py | _get_soap_req | Service {} found in self.services. Continuing.".format(service_name))

        service_data = self.services[service_name]
        url = "{}://{}:{}{}".format(self.protocol, self.ip, self.port, service_data["controlURL"])

        # Build a SSL Context to disable certificate verification.
        html_hdr = {'Host': self.ip,
                    'CONTENT-TYPE': 'text/xml; charset="utf-8"',
                    'SOAPACTION': '"{}#{}"'.format(service_data["serviceType"], action)}

        soap_hdr = self._get_soap_header()

        data = ('<?xml version="1.0" encoding="utf-8"?>\n' +
                '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n' +
                soap_hdr + '\n<s:Body>\n\t<u:' + action + ' xmlns:u="' +
                service_data["serviceType"] + '">')

        for key in attr_list:
            data += ('\n\t\t<{}>{}</{}>'.format(key, attr_list[key], key))

        data += ('\n\t</u:{}>\n</s:Body>\n</s:Envelope>'.format(action))

        return urllib2.Request(url, data=data, headers=html_hdr)

    def set_soap_action(self, service_name, action, attr_list):
        """

        :param service_name:
        :param action:
        :param attr_list:
        :return:
        :rtype: {}
        """
        # Build a SSL Context to disable certificate verification.
        self.logger.debug("fritz.py | Entering set_soap_action(service_name = {}, action={}, attr_list={})".format(service_name, action, attr_list))

        ctx = ssl._create_unverified_context()

        for x in range(0, 2):
            request = self._get_soap_req(service_name, action, attr_list)
            if not request:
                continue

            try:
                response = urllib2.urlopen(request, timeout=self.time_out, context=ctx)
                response_data = response.read()

                reply = re.findall(r"<(.*?)>(.*?)</.*?>", response_data, re.MULTILINE)
                data = {}
                for pair in reply:
                    data[pair[0]] = pair[1]

                if "Status" in data:
                    auth_status = data["Status"]
                    self.logger.debug("fritz.py | set_soap_action | auth_status: {}".format(auth_status))
                    if auth_status == "Unauthenticated":
                        self.logger.debug("fritz.py | set_soap_action | Authentication try no. {}".format(self.recursion_cnt))
                        if self.recursion_cnt < 2:
                            self.realm = str()
                            self.nonce = str()
                            self.auth = str()
                            self.recursion_cnt = self.recursion_cnt + 1
                            self._get_auth_data(response_data)
                            data = self.set_soap_action(service_name, action, attr_list)
                    else:
                        self.recursion_cnt = 0
                        self.logger.debug("fritz.py | set_soap_action | data: {}".format(data))

                return data

            except urllib2.HTTPError as e:
                response_data = e.read()
                error_code = re.findall('<errorCode>(.*?)</errorCode>', response_data, flags=re.S)
                error_descr = re.findall('<errorDescription>(.*?)</errorDescription>', response_data, flags=re.S)
                raise Exception("set_soap_action | HTTPError: {} ({})".format(error_descr[0], error_code[0]) +
                                    ", service_name: {}".format(service_name) +
                                    ", action: {}".format(action) +
                                    ", attr_list: {}".format(json.dumps(attr_list)))

            except urllib2.URLError as e:
                # 10061 # Computer verweigert Verbindung
                # 10065 # Der Host war bei einem Socketvorgang nicht erreichbar
                error_no = e.args[0][0]
                raise Exception("fritz.py | set_soap_action | URLError: {}".format(error_no) +
                                    ", service_name: {}".format(service_name) +
                                    ", action: {}".format(action) +
                                    ", attr_list: {}".format(json.dumps(attr_list)))

    def _get_auth_data(self, data):
        """

        :param data:
        :return:
        :rtype: bool
        """
        if self.nonce and self.realm and self.auth:
            self.logger.debug("fritz.py | get_auth_data | Auth data already existing. "
                              "Will be deleted if a connection attempt fails.")
            return False

        nonce_match = re.search(r"<Nonce>(.*?)</Nonce>", data)
        realm_match = re.search(r"<Realm>(.*?)</Realm>", data)
        if nonce_match is None or realm_match is None:
            raise Exception("fritz.py |get_auth_data | No nonce or realm in provided data. Aborting.")

        self.nonce = nonce_match.group(1)
        self.realm = realm_match.group(1)

        if not self.user or not self.password:
            raise Exception("fritz.py |get_auth_data | User or Password not set. Aborting.")

        secret = hashlib.md5("{user}:{realm}:{pw}".format(user=self.user, realm=self.realm, pw=self.password))
        response = hashlib.md5(secret.hexdigest() + ":" + self.nonce)

        self.auth = response.hexdigest()
        if self.nonce and self.auth and self.realm:
            return True

        return False

