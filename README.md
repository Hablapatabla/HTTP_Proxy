# HTTP_Proxy

## An HTTP Proxy implemented by Lucas Loaiza and Trevor Russo

This proxy takes HTTP GET and CONNECT method requests. The proxy depends on RFC 2616 5.1.2 and RFC 7231 4.3.6. These RFC's dictate that clients of a proxy must use an absolute URL if sending an HTTP GET request. Clients must send a URL of form hostname:portno if sending a CONNECT request. Well-behaved browsers should be following these guidelines - this could only be a problem with non-major browsers.

## Getting started (quick guide)
1. Configure your browser (Firefox recommended) and machine to trust the myCA.pem certificate in the repo.
2. Ensure myCA.pem is in the same directory as the proxy.
3. Create an empty folder called 'certificates'. <-- This is critical!

## Getting started (in-depth)

The included certificate authority myCA.pem and corresponding private key myCA.key should work for this proxy. However, your environment needs to be configured to trust it.

### Windows / Linux
Use [this guide](https://thomas-leister.de/en/how-to-import-ca-root-certificate/) to add the myCA.pem root certificate to your trusted store. If the .pem file is not accepted, make a copy with the .crt extension - .pem and .crt are 1-to-1 formats, so no more work should be necessary.

### OS X
1. Open the 'Keychain Access' application. This is usually in your 'Utilities' folder.
2. Navigate to 'File' > 'Import items'.
3. Import the myCA.pem file. Make sure this file is in the same directory as the proxy executable.
4. Right click the imported certificate and select 'Get info'
5. Open the 'Trust' dropdown and set the 'When using this certificate: ' field to 'Always trust'.

### Browser
Most browsers use the machines local trust store. However, browsers like Firefox, our recommended browser, have their own certificate chain. This will need to be configured as well.
1. Go to your Firefox settings
2. Search 'certificates'
3. 'View certificates' > 'Authorities'
4. Select 'Import...', and import the myCA.pem file.

### Certificates folder
Finally, you need to create an empty folder in the same directory as the project called 'certificates'. Due to the nature of using the OpenSSL command line to do a lot of the heavy lifting, it is critical that this directory exists, otherwise, the proxy will not work. This folder will be filled with .pem certificates and .key private keys for each new hostname visited as browsing continues. These certificates should have the used hostname as the Subject Common Name, and should have that hostname as well as the hostname with a 'www.' prefix as Subject Alternative Names. These can be viewed with the command 'certtool d [cert.'hostname'.pem]'.

It is highly recommended to clear out this folder every time before starting the proxy! Otherwise, old certificates could be re-used, and potentially introduce errors as the proxy tries to Accept an SSL connection with your browser, using an old certificate.

## Sites known not to be supported
This is a brief list of sites that are known to not work with the proxy. The reason why these sites are not compatible with the proxy is unclear at this time.

* leetcode.com
*
