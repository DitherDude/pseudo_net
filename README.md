# Quick start guide:
In the root folder of this program, create a file called `config`.
> [!IMPORTANT]
> Values are dynamically read from the `config` file, meaning that changes are essentially applied **immediately**. If there is valid reasoning for there to be an option for the `config` file to be RAM loaded (to make it easier for multiple instances of the server to be run with custom configuration via scripts), I *may* add this functionality. For now it is not on the roadmap.

In the file, write the following:
> [!NOTE]
> `PATH` is the only **required** variable. All the others can be ommited, and the server will assume the default value. The same applies if the input is incorrect, e.g. `PORT: ABC` will use the default value of `15496`.
```
PATH: mysql://root:password@localhost:3306/PSEUDO_NET
```
`PATH`: URL of the MYSQL database. `root:password` is the username and password for the sql server, and where `PSEUDO_NET` is the database name.

> [!TIP]
> All values shown in the code blocks below are the server's default/fallback values. To modify these variables, add the code blocks to the `config` file.

`PORT`: Defines the desired valid (u16) port number.
```
PORT: 15496
```

`BITS`: Defines the desired bit-length of the RSA Key.
```
BITS: 2048
```

For the next three blocks, `CLIENT` refers to the device (IP) trying to sign in, whereas `USER` is the account the CLIENT is trying to sign in.
```
CLIENT-PENALTY: 50
USER-PENALTY: 50
```
`PENALTY`: Controls how many penalty points the client/user is awarded on an incorrect login attempt.
```
CLIENT-FORGIVE: -100
USER-FORGIVE: -100
```
`FORGIVE`: Controls how many penalty points the client/user is awarded on successful login attempt.
```
CLIENT-LOCKOUT: 1000
USER-LOCKOUT: 1000
```
`LOCKOUT`: Control the minimum amount of points a client/user must have to be locked out.
> [!WARNING]
> There is no current method to 'unlock' a locked account without manually editing the SQL Database.
