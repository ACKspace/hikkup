#!/usr/bin/env python3

'''
Inspiration:
AES encryption from:    https://gist.github.com/forkd/7ed4a8392fe7b69307155ab379846019
TCP proxy from:         https://medium.com/@gdieu/build-a-tcp-proxy-in-python-part-1-3-7552cd5afdfe
Simple hexdump from:    https://gist.github.com/JonathonReinhart/509f9a8094177d050daa84efcd4486cb
get_ip from:            https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
'''

from sys import exit as sys_exit
import select
import socket
import ssl
import re
import hashlib
from Crypto.Cipher import AES
import time

#pycrypto
key = None 
cipher = None
iv = None


def xor(data, key): 
    return bytearray(a^b for a, b in zip(*map(bytearray, [data, key])))

class Hikkup():
    def __init__(self, _local_addr="", _gateway_addr=None, _gateway_port=None, _service_port=None, _ssl_service_port=None, _event_service_port=None ):
        self.lsock = []         # List of local sockets
        self.msg_queue = {}     # Map of connected sockets

        self.local_addr         = _local_addr

        self.gateway_addr       = _gateway_addr
        self.gateway_port       = _gateway_port

        self.service_port       = _service_port
        self.ssl_service_port   = _ssl_service_port
        self.event_service_port = _event_service_port
        self.addresses = { self.event_service_port: "34.246.99.36" }

    def tcp_servers(self):
        try:
            sock_gateway = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                    server_side=True,
                                    certfile="cert.pem",
                                    keyfile="cert.pem",
                                    ssl_version=ssl.PROTOCOL_TLSv1_2 )

            sock_gateway.setblocking(0)
            sock_gateway.bind((self.local_addr, int(self.gateway_port)))
            sock_gateway.listen(10)

            # Add host socket to the list
            self.lsock.append(sock_gateway)
            print('[*] Listening on {0} {1}{2}'.format(self.local_addr,self.gateway_port," (SSL)"))

            sock_ssl_service = None
            if ( self.ssl_service_port ):
                sock_ssl_service = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                        server_side=True,
                                        certfile="cert.pem",
                                        keyfile="cert.pem",
                                        ssl_version=ssl.PROTOCOL_TLSv1_2 )

                sock_ssl_service.setblocking(0)
                sock_ssl_service.bind((self.local_addr, int(self.ssl_service_port)))
                sock_ssl_service.listen(10)

                # Add host socket to the list
                self.lsock.append(sock_ssl_service)
                print('[*] Listening on {0} {1}{2}'.format(self.local_addr,self.ssl_service_port," (SSL)"))

            sock_service = None
            if ( self.service_port ):
                sock_service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_service.setblocking(0)
                sock_service.bind((self.local_addr, int(self.service_port)))
                sock_service.listen(10)

                # Add host socket to the list
                self.lsock.append(sock_service)
                print('[*] Listening on {0} {1}{2}'.format(self.local_addr,self.service_port,""))

            if ( self.event_service_port ):
                sock_event_service = ssl.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                        server_side=True,
                                        certfile="cert.pem",
                                        keyfile="cert.pem",
                                        ssl_version=ssl.PROTOCOL_TLSv1_2 )

                sock_event_service.setblocking(0)
                sock_event_service.bind((self.local_addr, int(self.event_service_port)))
                sock_event_service.listen(10)

                # Add host socket to the list
                self.lsock.append(sock_event_service)
                print('[*] Listening on {0} {1}{2}'.format(self.local_addr,self.event_service_port," (SSL)"))

            while True:
                readable, writable, exceptional = select.select(self.lsock, [], [])
                for s in readable:
                    #if s == sock_gateway or s == sock_ssl_service or s == sock_service or s == sock_event_service:
                    rserver = None
                    if s == sock_gateway:
                        rserver = self.remote_conn( self.gateway_addr, self.gateway_port, True )
                    elif s == sock_ssl_service:
                        rserver = self.remote_conn( self.addresses[self.gateway_port], self.ssl_service_port, True )
                    elif s == sock_service:
                        rserver = self.remote_conn( self.addresses[self.gateway_port], self.service_port, False )
                    elif s == sock_event_service:
                        rserver = self.remote_conn( self.addresses[self.event_service_port], self.event_service_port, True )

                    if rserver:
                        client, addr = s.accept()
                        print('[*] Accepted connection {0} {1}'.format(addr[0], addr[1]))
                        self.store_sock(client, rserver)
                        break
                    #else:
                    #    print('the connection with the remote server can\'t be \
                    #    established')
                    #    #print('Connection with {} is closed'.format(addr[0]))
                    #    print('Connection with ? is closed')
                    #    #client.close()

                    data = self.received_from(s, 10)

                    if len(data) == 0:
                        #print( "no data on {}".format( s.getpeername() ) )
                        self.close_sock(s)
                        break
                    else:
                    # Manipulate data here..
                    # 
                        print('[*] Received {0} bytes from {1} on port {2} -> {3}'.format( len(data), s.getpeername()[0], s.getpeername()[1], s.getsockname()[1] ))
                        parsed = re.match( b"^([\s\S]{32})([\s\S]*)([\s\S]{32})$", data )
                        if parsed:
                            binary = parsed.group(1)
                            xml = parsed.group(2)
                            
                            print("[+] Binary:" )
                            self.hexdump( binary )
                            try:
                                decodedxml = xml.decode()
                                print("[+] XML:" )
                                print( decodedxml )
                            except Exception as e:
                                print('[-] XML decode failed.')
                                self.hexdump( xml ) 
                                print('FOOTER.')
                                footer = xml[-16:]
                                self.hexdump( footer )
                                if ( cipher ):
                                    print('[+] decrypt xml:')
                                    decrypted = cipher.decrypt( xml )
                                    print( decrypted )

                                    # Store last 8 bytes from encrypted xml into iv
                                    print( "xor footer with iv:" )
                                    footer = xor( footer, b'01234567' + ( '\0' * 8 ).encode() )
                                    self.hexdump( footer );

                                    print( "xor first 16 bytes against known xml:" )
                                    xorheader = xor(decrypted, b'<?xml version="1')
                                    self.hexdump( xorheader );
                                    #iv


                                    iv = bytes(footer)
                                    cipher = AES.new(key, AES.MODE_CBC, iv)


                            md5hash = hashlib.md5( parsed.group(2) )
                            if md5hash.hexdigest() == parsed.group(3).decode():
                                print( "[+] md5 matches xml part" )
                            else:
                                print( "[!] no xml md5 match (provided, calculated):" )
                                print( "    {}".format( parsed.group(3).decode() ) )
                                print( "    {}".format( md5hash.hexdigest() ) )

                            #result = re.match( b"(.*Address=\")(\d+\.\d+\.\d+\.\d+)(\".*)", xml )
                            #[\s\S]
                            result = re.match( b"(.*Address=\")([^\"]+)(\"[\s\S]*)", xml )
                            if result:
                                # Store translated address on 'server port'
                                self.addresses[s.getpeername()[1]] = result.group(2).decode()
                                print("[*] Replaced Address: " + result.group(2).decode() )
                                xml = result.group(1) + bytearray(self.local_addr) + result.group(3)

                            result = re.match( b"([\s\S]*?Domain=\")(\d+\.\d+\.\d+\.\d+)(\"[\s\S]*)", xml )
                            if result:
                                print("[*] Replaced Domain: " + result.group(2).decode() )
                                xml = result.group(1) + bytearray(self.local_addr) + result.group(3)


                            # TODO: listen to 6800+6900 and share the key
                            result = re.match( b"[\s\S]*?<Crypto Algorithm=\"AES128\" Key=\"([0-9a-f]{16})\"/>[\s\S]*", xml )
                            if result:
                                key = result.group(1).decode()
                                print("[+] found key: {}".format( key ) )
                                #iv = key
                                # Authorization Code: base 64
                                # 
                                # DevIdentificationCode: hex e42d625becfe94b93d509183edbef571
                                # 
                                # 
                                # 
                                # 
                                # 
                                # 
                                # https://stackoverflow.com/questions/26928012/wrong-16-bytes-in-decryption-using-aes
                                # 

                                #cipher = AES.new(key, AES.MODE_ECB)
                                #cipher = AES.new(key, AES.MODE_CTR)

                                #iv = ( '\0' * 16 ).encode()
                                iv = b'01234567' + ( '\0' * 8 ).encode()
                                cipher = AES.new(key, AES.MODE_CBC, iv) # update iv...
                                #byteData[mx : mx+7] = 1, 2, 3, 4, 5, 6, 7
                                #cipher = AES.new(key, AES.MODE_CFB, iv) # nope
                                #cipher = AES.new(key, AES.MODE_OFB, iv)

                            #print("[+] XML:" )
                            #print( xml.decode() )

                            md5hash = hashlib.md5( xml )

                            data = binary + xml + md5hash.hexdigest().encode()

                        else:
                            print("[!] Unknown data." )
                            self.hexdump(data)

                        # Forward data to 'opposite' socket
                        self.msg_queue[s].sendall(data)
                            #self.hexdump(data)
        except KeyboardInterrupt:
            print ('[*] Ending server')        
        except Exception as e:
            print('[!] Something went wrong..')
            print(e)
            sys_exit(0)      
        finally:
            sys_exit(0)

    def remote_conn(self, _host, _port, _ssl):
        try:
            print ('[ ] Accepting on port {}{}'.format( _port, (""," (ssl)")[_ssl] ) )
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if ( _ssl ):
                remote_sock = ssl.wrap_socket(remote_sock, ssl_version=ssl.PROTOCOL_TLSv1_2)

            remote_sock.connect(( _host, int( _port )))
            return remote_sock
        except Exception as e:
            print( "[!] Something went wrong: {}".format( e ) )
            return False

    def store_sock(self, client, rserver):
        # [Errno 111] Connection refused
        #print ('[ ] storing sock'.format(sock.getpeername()[0], sock.getpeername()[1] ) )

        # Add incoming client and connected remote socket to the list
        self.lsock.append(client)
        self.lsock.append(rserver)

        # Set connection reference map (client <-> server)
        self.msg_queue[client] =  rserver
        self.msg_queue[rserver] =  client

    def close_sock(self, sock):
        #s.getsockname()[1]
        print ('[-] End of connection with {} {}'.format(sock.getpeername()[0], sock.getpeername()[1] ) )

        # Get 'opposite' connection
        serv = self.msg_queue[ sock ]
        clnt = self.msg_queue[ serv ]

        # Remove 'opposite' and its own connection from the list of local sockets
        self.lsock.remove( serv )
        self.lsock.remove( clnt )

        # Close connections
        self.msg_queue[serv].close()
        self.msg_queue[clnt].close()

        # Remove connections from the hashmap
        del self.msg_queue[clnt]
        del self.msg_queue[serv]
        time.sleep( 1 )

    def received_from(self, sock, timeout):
        data = ""
        sock.settimeout(timeout)
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                data =+ data
        except:
            pass
        return data

    def hexdump(self, data, length=16):
        filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
        lines = []
        digits = 4 if isinstance(data, str) else 2
        for c in range(0, len(data), length):
            chars = data[c:c+length]
            hex = ' '.join(["%0*x" % (digits, (x)) for x in chars])
            printable = ''.join(["%s" % (((x) <= 127 and filter[(x)]) or '.') for x in chars])
            lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
        print(''.join(lines))

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# gateway IP, gateway port, service, sslservice, eventservice
hikkup = Hikkup( get_ip(), "52.212.63.175", 8555, 6800, 6900, 7400 );
hikkup.tcp_servers()

