# Quick start guide:
In the root folder of this program, create a file called `config.yml`.
> [!IMPORTANT]
> Values are dynamically read from the `config.yml` file, meaning that changes are essentially applied **immediately**. If there is valid reasoning for there to be an option for the `config.yml` file to be RAM loaded (to make it easier for multiple instances of the server to be run with custom configuration via scripts), I *may* add this functionality. For now it is not on the roadmap.

In the file, write the following:
> [!NOTE]
> `path` is the only **required** variable. All the others can be ommited, and the server will assume the default value. The same applies if the input is incorrect, e.g. `port: ABC` will use the default value of `15496`.
```yaml
path: "mysql://root:password@localhost:3306/PSEUDO_NET"
```
`path`: URL of the MYSQL database. `root:password` is the username and password for the sql server, and where `PSEUDO_NET` is the database name.

> [!TIP]
> All values shown in the code blocks below are the server's default/fallback values. To modify these variables, add the code blocks to the `config` file.

`port`: Defines the desired valid (u16) port number.
```yaml
port: 15496
```

`bits`: Defines the desired bit-length of the RSA Key.
```yaml
bits: 2048
```

For the next three blocks, `client` refers to the device (IP) trying to sign in, whereas `user` is the account the CLIENT is trying to sign in.
> [!IMPORTANT]
> As this is a `YAML` filetype, it is **crucial** that the indentations shown in the following code block are staggered as shown.
```yaml
client:
  penalty: 50
  forgive: -100
  lockout: 1000
user:
  penalty: 50
  forgive: -100
  lockout: 1000
```
`penalty`: Controls how many penalty points the client/user is awarded on an incorrect login attempt.

`forgive`: Controls how many penalty points the client/user is awarded on successful login attempt.

> [!NOTE]
> `forgive` is negative as we wish to inverse the penalty awarded on a failed login attempt. `forgive` is usually greater (absolute comparison) than `penalty` to not be too harsh on the user, who is likely to type the password incorrectly at some point. 

`lockout`: Controls the minimum amount of penalty points a client/user must have to be locked out.

> [!WARNING]
> There is no current method to 'unlock' a locked account without manually editing the SQL Database. Use with caution.