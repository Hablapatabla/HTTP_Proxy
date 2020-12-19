import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = ('localhost', 9994);
print('starting up on %s port %s' % server_address)
sock.bind(server_address)
sock.listen(1)

def get_hosts():
    csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    csock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('127.0.0.1', 9996)
    csock.connect(server_address)
    host_list = []

    try:
        message = 'LIST / HTTP/1.1\r\nPreferred: apple.com, google.com\r\n\r\n'
        csock.sendall(message.encode())
        while True:
            host = csock.recv(100)
            if not host:
                break
            else:
                host_list.append(host)
    finally:
        csock.close()
        return host_list


while True:
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        host_list = get_hosts()
        new_list = []
        for host in host_list:
            new_list.append(str(host.decode()).strip('\x00'))
        new_list = list(set(new_list))

        webpage = '<!DOCTYPE HTML><html><body><h1>Test Site</h1><ul>'
        for host in new_list:
            webpage = webpage + '<li>' + host + '</li>'
        webpage = webpage + '</ul></body></html>'
        header = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
        header = header + str(len(webpage))
        header = header + '\r\n\r\n'
        response = header + webpage
        chunk = connection.recv(2048)
        connection.sendall(response.encode())
    finally:
        connection.close()
