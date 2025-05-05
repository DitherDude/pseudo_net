# Quick start guide:
In the root folder of this program, create a file called `config`.
In the file, write the following:
```
PATH: mysql://root:password@localhost:3306/PSEUDO_NET
```
Where `root:password` is the username and password for the sql server, and where `PSEUDO_NET` is the database name.

The program by default runs on port `15496`. to change this, add the following to `config`:
```
PORT: 12345
```
Where `12345` is the desired valid (u16) port number.

Additionally, the server by default uses an `RSA-2048` key for asymmetric encryption. To change this, add the following to `config`:
```
BITS: 4096
```
Where `4096` is the desired bit-length of the RSA Key.