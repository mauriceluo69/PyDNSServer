import argparse
import socketserver
import struct
import dns.resolver
import time


def SetupParas():
    parser = argparse.ArgumentParser(description='Domain Name System')

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", action="store_true", help="Level-1 Debuging")
    group.add_argument("-dd", action="store_true", help="Level-2 Debuging")

    parser.add_argument("--addr", help="DNS server IP address", type=str)
    parser.add_argument("--filename", help="\"dnsrelay.txt\"", type=str)
    return parser


def File2Dict(fileName):
    f = open(fileName, 'r')
    data = f.read()
    f.close()
    contents = data.split('\n')
    res = {}
    for content in contents:
        temp = content.split(' ')
        res.update({temp[1]: temp[0]})
    return res


def ParasHandler(parseRe):
    address = parseRe.addr
    fileName = parseRe.filename

    if not (parseRe.d or parseRe.dd):
        print("Non-debuging infomation output mode...")
        if address or fileName:
            print('Error.We accept no paras in this mode. Please just use \'dnsrelay\'')
            exit(-1)
        _mode = 1

    if parseRe.d:
        print("Debuging infomation level-1...")
        if address is None or fileName is None:
            print('Error. We need 2 paras [--addr] [--filename] in this mode. Please check again.')
            exit(-1)
        _mode = 2

    if parseRe.dd:
        print("Debuging infomation level-2...")
        if not (address is not None and fileName is None):
            print('Error. We only accept 1 paras [--addr] in this mode. Please check again.')
            exit(-1)
        _mode = 3

    if _mode == 2:
        hostsFromFile = File2Dict(fileName)
    else:
        hostsFromFile = File2Dict('dnsrelay.txt')
    return dict(mode=_mode, hosts=hostsFromFile, addr=address)


def DNSQueryDestructor(info):
    i = 1
    name = ''
    while True:
        d = info[i]
        if d == 0:
            break
        if d < 32:
            name = name + '.'
        else:
            name = name + chr(d)
        i = i + 1
    _querybytes = info[0:i + 1]
    (_type, classify) = struct.unpack('>HH', info[i + 1:i + 5])
    _len = i + 5
    return dict(domain=name, queryBytes=_querybytes, queryType=_type, queryClassify=classify, queryLen=_len)


def DNSAnsConstructor(ip):
    _name = 49164
    _type = 1
    _classify = 1
    _ttl = 5000
    _datalength = 4
    res = struct.pack('>HHHLH', _name, _type, _classify, _ttl, _datalength)
    s = ip.split('.')
    res += struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
    return res


def DNSConstructor(info, ip):
    answers = 1
    flags = 33152
    hearder = info['header']
    queryInfo = info['queryInfo']
    res = struct.pack('>HHHHHH', hearder['id'], flags, hearder['quests'], answers, hearder['author'], hearder['addition'])
    res += queryInfo['queryBytes'] + struct.pack('>HH', queryInfo['queryType'], queryInfo['queryClassify'])
    res += DNSAnsConstructor(ip)
    return res


def DNSDestructor(info):
    (_id, _flags, _quests, _answers, _author, _addition) = struct.unpack('>HHHHHH', info[0:12])
    _header = dict(id=_id, flags=_flags, quests=_quests, answers=_answers, author=_author, addition=_addition)
    return dict(header=_header, queryInfo=DNSQueryDestructor(info[12:]))


def GetIP(server, domain):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['202.106.0.20']
    try:
        res = my_resolver.query(domain, 'A')
        return str(res[0])
    except Exception:
        return None


def DebugInfoLevel2(time, domain, _id):
    print('** Time =', time, '\t', 'ID =', _id, '\t', domain)


def DebugInfoLevel3(currTime, dnsRequest, res):
    print('------------------------------')
    print('TIME:\t\t', currTime)
    print('ID:\t\t', dnsRequest['header']['id'])
    print('flag:\t\t', dnsRequest['header']['flags'])
    print('quest:\t\t', dnsRequest['header']['quests'])
    print('answer:\t\t', dnsRequest['header']['answers'])
    print('author:\t\t', dnsRequest['header']['author'])
    print('addition:\t', dnsRequest['header']['addition'])
    print('domain:\t\t', dnsRequest['queryInfo']['domain'])
    print('type:\t\t', dnsRequest['queryInfo']['queryType'])
    print('classify:\t', dnsRequest['queryInfo']['queryClassify'])
    print('len:\t\t', dnsRequest['queryInfo']['queryLen'])
    print('------------------------------')
    print('RESULT:\t\t', res)
    print('------------------------------\n\n\n')


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        currTime = str(int(time.time()))
        dnsRequest = DNSDestructor(self.request[0].strip())
        socketInfo = self.request[1]
        if dnsRequest['queryInfo']['queryType'] == 1:
            # A records
            hostsInFile = DNSServer.hosts
            requestDomain = dnsRequest['queryInfo']['domain']
            if requestDomain in hostsInFile:
                # record in file
                if not hostsInFile[requestDomain] == '0.0.0.0':
                    # not 0.0.0.0
                    if DNSServer.mode == 2:
                        DebugInfoLevel2(currTime, requestDomain, dnsRequest['header']['id'])
                    elif DNSServer.mode == 3:
                        DebugInfoLevel3(currTime, dnsRequest, hostsInFile[requestDomain])
                    socketInfo.sendto(DNSConstructor(dnsRequest, hostsInFile[requestDomain]), self.client_address)
                else:
                    # 0.0.0.0
                    if DNSServer.mode == 2:
                        DebugInfoLevel2(currTime, requestDomain, dnsRequest['header']['id'])
                    elif DNSServer.mode == 3:
                        DebugInfoLevel3(currTime, dnsRequest, hostsInFile[requestDomain])
                    socketInfo.sendto(self.request[0].strip(), self.client_address)
            else:
                # ask higher level DNS server
                resFromRemote = GetIP(DNSServer.addr, requestDomain)
                if resFromRemote is not None:
                    # response from remote DNS server
                    if DNSServer.mode == 2:
                        DebugInfoLevel2(currTime, requestDomain, dnsRequest['header']['id'])
                    elif DNSServer.mode == 3:
                        DebugInfoLevel3(currTime, dnsRequest, resFromRemote)
                    socketInfo.sendto(DNSConstructor(dnsRequest, resFromRemote), self.client_address)
                else:
                    # no answer from remote DNS server
                    if DNSServer.mode == 2:
                        DebugInfoLevel2(currTime, requestDomain, dnsRequest['header']['id'])
                    elif DNSServer.mode == 3:
                        DebugInfoLevel3(currTime, dnsRequest, 'NOT FOUND')
                    socketInfo.sendto(self.request[0].strip(), self.client_address)
                    # print('NOT FOUND')
        else:
            # NOT an A type request
            socketInfo.sendto(self.request[0].strip(), self.client_address)


class DNSServer:
    def __init__(self, port=53, hosts={}, mode=0, addr=''):
        DNSServer.hosts = hosts
        self.port = port
        DNSServer.mode = mode
        DNSServer.addr = addr
        print('Current remote DNS server:', DNSServer.addr)

    def start(self):
        addr = ("127.0.0.1", self.port)
        server = socketserver.ThreadingUDPServer(addr, DNSHandler)
        server.serve_forever()


if __name__ == "__main__":
    parser = SetupParas()
    setupInfo = ParasHandler(parser.parse_args())
    remote = setupInfo['addr']
    if remote is None:
        remote = '202.106.0.20'
    dnsServer = DNSServer(hosts=setupInfo['hosts'], mode=setupInfo['mode'], addr=remote)
    dnsServer.start()
