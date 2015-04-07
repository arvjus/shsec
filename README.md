Project: shsec (SharedSecret)
Author:  Arvid Juskaitis arvydas.juskaitis@gmail.com
License: GPL

SharedSecret is a software used to negotiate a shared secret (password) by 
two hosts in secure way over the Internet. It is written in C, based on 
client/server architecture with initial intention to run on POSIX-Compliant 
Operating Systems. 
Client application is provided (shsec), so it could be used to agree on 
password between two users or create preshared-key for VPN. It could also 
be used from other applications; possibly simple API will be provided to 
hide client-server communication details. 
The concept of tag@peer helps to identify keys on both sides. There is no
way to create several keys between two hosts with the same tag. Existing
key cannot be replaced by a new key, it must expire first or diferrent tag
should be used.

Funcionality is quite simple. A daemon is running on each side (no root 
privileges required) which accepts requests from peer and initiates key exchange 
upon client request. It uses Diffie-Hellman key agreement algorithm and a
simple protocol based on TCP to exchage payloads. 

See shsec.txt for detailed technical description.

Installation instruction is provides in INSTALL file.
For more information, please, read documentation and manuals in docs/ dir 
and (of cource!) take a look at the source code. Note for best readability 
tab size = 4 sould be used.


Some usage examples (assume shsecd is running):

1. to initiate key exchange, labeled 'secret1' exchange on hostA to hostB and 
print result key to stdout:

hostA$ shsec -i secret1@hostB 

2. to retrieve the same key on peer site without deleting from the local key database: 

hostB$ shsec -k secret1@hostA

3. save a key into secret.key file in binary (raw) format:

hostB$ shsec -k -F raw -o secret.key secret1@hostA

4. to run two instances of daemon on the same machine:

create a config file and specify port (eg 10001 and 10002) and socket, keydb, 
pid files for each daemon instance:

$ shsecd -d -c shsec1.conf
$ shsecd -d -c shsec2.conf


then initiate key request from one server and retrieve a key on another:

$ shsec -vi -S shsec1.sock secret1@localhost:10002 
$ shsec -vk -S shsec2.sock secret1@localhost 


try 'shsec -h' to get more options.

