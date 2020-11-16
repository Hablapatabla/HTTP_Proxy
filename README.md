# HTTP_Proxy

## An HTTP Proxy implemented by Lucas Loaiza and Trevor Russo

This proxy takes HTTP GET and CONNECT method requests. The proxy depends on RFC 2616 5.1.2 and RFC 7231 4.3.6. These RFC's dictate that clients of a proxy must use an absolute URL if sending an HTTP GET request. Clients must send a URL of form hostname:portno if sending a CONNECT request.
