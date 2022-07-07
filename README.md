# Infocyte Extensions
The [Infocyte](https://www.infocyte.com) platform is an agentless Threat Hunting
and Incident Response platform. In addition to the plethora of native host data
collection and analysis provided by default, users are able to define their own
collections and response actions to be performed on endpoints and servers. Here
you will find examples and contributed extensions which can be easily loaded
into the Infocyte platform.

**This repo contains:**
- [Infocyte Extensions](#infocyte-extensions)
    - [Overview](#overview)
        - [Collection](#collection)
        - [Response](#response)
    - [Usage](#usage)
    - [API Reference](#api-reference)
      - [Logging and Output](#logging-and-output)
      - [Environmental](#environmental)
      - [Shell Commands](#shell-commands)
      - [File System](#file-system)
      - [Data](#data)
      - [Network](#network)
      - [Web](#web)
      - [Process](#process)
      - [Registry](#registry)
      - [Hashing](#hashing)
      - [Recovery](#recovery)
      - [Analysis](#analysis)
        - [Autostarts](#autostarts)
        - [Artifacts](#artifacts)
        - [Yara](#yara)
      - [Status](#status)
      - [Extras](#extras)
    - [Examples](#examples)
    - [Contributing](#contributing)
    - [Feature Requests](#feature-requests)
    - [Learn lua](#learn-lua)

### Overview
The Infocyte extension system is built on top of [Lua 5.3](https://www.lua.org),
which provides an easy to deploy, cross platform, and feature-rich library of
built-in functions. This includes file system, string , I/O, math, operations
(among others). Refer to the
[Lua Reference Manual](https://www.lua.org/manual/5.3/contents.html) for
detailed documentation on usage or you can click [here](#learn-lua) for Lua
tutorials.

In addition to the Lua standard library, Infocyte exposes capabilities
of its' agent and endpoint collector ("Survey") that make interacting with host
operating systems more powerful and convenient. This extended language is the
real engine that powers the extension system. With these enhancements, extension
authors can easily perform web requests, access the windows registry, terminate
running processes, even add items to the existing result set retrieved
by the platform's standard host collection routine. Examples also exist to call
other types of scripts like Powershell, Python or Bash depending on availability
of the relevant interpreter on the host.

There are currently two types of extensions supported: Collection & Response.

##### Collection
Collection extensions extend what is collected or inspected at scan time. This
can be additional registry keys or files to be analyzed or YARA signatures to be
used on the host-side. Threat statuses can be flagged based on your logic and
text fields are available for arbitrary data collection up to 3MB in size. For
large evidence collection, we will have functions available to push data direct
from the host to a user provided AWS S3 Bucket, sFTP, or SMB share.

##### Response
Response Extensions cause direct changes to remote systems. These can be
remediation actions like host isolation, malware killing, host hardening
routines (like changing local logging configurations), or other installing
3rd party tools.

### Usage
After logging into your Infocyte instance (with an administrator role) simply navigate to `Admin->Extensions`.

Infocyte default extensions are automatically loaded/updated but start in the disabled state.  Enable the 
extensions (by marking it "Active") you wish to use or your can create your own by copying one of the 
default extensions or starting from scratch.

Hitting save on a new or edited extension will perform a syntax validation and if everything checks out, will
save the newly created extension for use. To make the extension available to deploy during a scan, 
make sure you click the `Active` column to enable it as an option.

Once an extension is created and activated, it can be chosen for execution during a scan of a target group.


### API Reference
Below is documentation surrounding the extended Lua API developed and provided
by Infocyte. This API can be broken down into various parts:

- [Infocyte Extensions](#infocyte-extensions)
    - [Overview](#overview)
        - [Collection](#collection)
        - [Response](#response)
    - [Usage](#usage)
    - [API Reference](#api-reference)
      - [Logging and Output](#logging-and-output)
      - [Environmental](#environmental)
      - [Shell Commands](#shell-commands)
      - [File System](#file-system)
      - [Data](#data)
      - [Network](#network)
      - [Web](#web)
      - [Process](#process)
      - [Registry](#registry)
      - [Hashing](#hashing)
      - [Recovery](#recovery)
      - [Analysis](#analysis)
        - [Autostarts](#autostarts)
        - [Artifacts](#artifacts)
        - [Yara](#yara)
      - [Status](#status)
      - [Extras](#extras)
    - [Examples](#examples)
    - [Contributing](#contributing)
    - [Feature Requests](#feature-requests)
    - [Learn lua](#learn-lua)

#### Logging and Output
These functions provide the only methods to capture output from scripts that are
run. Using standard Lua `print()` or `io.write()` will cause data to be written
to standard output, but not captured and transmitted back to the Infocyte
platform.

| Function | Description |
| --- | --- |
| **hunt.log(string)** | Captures the input value and saves it to the extension output object to be viewed later in the Infocyte console. |
| **hunt.warn(string)** | Writes a string to the `warning` log level of the survey, as well as capture to the script output. |
| **hunt.error(string)** | Writes a string to the `error` log level of the survey, as well as capture to the script output. |
| **hunt.verbose(string)** | Writes a string to the `verbose` log level of the survey, as well as capture to the script output. |
| **hunt.debug(string)** | Writes a string to the `debug` log level of the survey, as well as capture to the script output. |
| **hunt.summary(string)** | Writes a short string to the `summary` of a response action. Only displayed if extension is ran as an interactive response. |

#### Environmental

**Example:**
```lua
host_info = hunt.env.host_info()
hunt.log("OS: " .. host_info:os())
hunt.log("Architecture: " .. host_info:arch())
hunt.log("Hostname: " .. host_info:hostname())
hunt.log("Domain: " .. host_info:domain())
```

| Function | Description |
| --- | --- |
| **hunt.env.os()** | Returns a string representing the current operating system. |
| **hunt.env.is_linux()** | Returns a boolean indicating the system is linux. |
| **hunt.env.is_windows()** | Returns a boolean indicating the system is windows. |
| **hunt.env.is_macos()** | Returns a boolean indicating the system is macos. |
| **hunt.env.host_info()** | Returns a table containing more host information.|
| **hunt.env.has_python()** | Returns a boolean indicating if any version of Python is available on the system. |
| **hunt.env.has_python2()** | Returns a boolean indicating if Python 2 is available on the system. |
| **hunt.env.has_python3()** | Returns a boolean indicating if Python 3 is available on the system. |
| **hunt.env.has_powershell()** | Returns a boolean indicating if Powershell is available on the system. |
| **hunt.env.has_sh()** | Returns a boolean indicating if the bourne shell is available on the system. |

#### Shell Commands

**Example:**
```lua
-- Runs a powershell command
cmd = "Get-Process | select -first 1"
hunt.log(f"Executing Powershell command: ${cmd}")
out, err = hunt.env.run_powershell(cmd)
if not out then
    hunt.error(err)
else
    hunt.log(out)
end
```

```lua
-- Runs a binary with arguments
out, err = hunt.env.run("ls", "-l", "/etc")
if not out then
    hunt.error(err)
else
    hunt.log(out)
end
```

```lua
-- split a command into an array for command runner
path = "C:\\windows\\temp\\amcacheparser.exe"
params = hunt.split(f"${path} -f C:\\Windows\\AppCompat\\Programs\\Amcache.hve --csv C:\\windows\\temp\\", " ")
out, err = hunt.env.run(params)
hunt.log(out)
```

| Function | Description |
| --- | --- |
| **hunt.env.run(path: string, arg1: string, arg2: string..)** |  Executes an application or utility (exe) with comma seperated parameters. Returns `strings` for stdout and sterr. Accepts an array or comma seperated list of strings as input. |
| **hunt.env.run_powershell(script: string)** | Runs a powershell script or command. Returns `string` for stdout and sterr |


#### File System

**Example**
```lua
for _,file in pairs(hunt.fs.ls('/etc/')) do
    print(file:full() .. ": " .. tostring(file:size()))
end
```

```lua
paths = hunt.fs.ls("C:/users/public/documents", { "recurse=1", "files"})
for _,p in pairs(paths) do 
  if string.find(p:path(), "csv$") then 
    table = hunt.csv.open(p:path())
    hunt.print_table(table)
  end
end
```

| Function | Description |
| --- | --- |
| **hunt.fs.ls(path1: string, path2: string, ..)** | Takes one or more paths and returns a list of files. |
| **hunt.path_exists(path: string)** | Returns a `boolean` if a path exists or not |
| **hunt.csv.open(path: string)** | Opens a CSV and reads it into a lua `table`. |

Filters can be used to cull the items returned by the `ls()` command. File size filters can take
numbers in either raw bytes, "kb", "mb", or "gb". Spaces in filters are not permitted.

```lua
-- hunt.fs.ls() takes an optional filters
-- use one or more of these together, but they must all be true for the item to return
opts = {
    "files", -- only return files
    "dirs", -- only return dirs
    "size>10mb", -- only return items greater than 10mb
    "size<1gb", -- only return items less than 1gb
    "size=123456", -- only return files whose size is 123456 bytes
    "recurse", -- recurse through all directories
    "recurse=3", -- recurse through directories, but only up to 3 levels deep
}

files = hunt.fs.ls('/usr/', opts)
```

```lua
-- the file object has some useful properties
file:full() -- returns the full path to the file
file:path() -- returns the path relative to the ls() 
file:name() -- returns the name of the file
file:size() -- returns the size of the file in bytes
file:is_dir() -- returns if the item is a directory
file:is_file() -- returns if the item is a non-directory file 
```

#### Data

**Examples:**


```lua
-- Base64 encode a string
psscript = [[
Install-Module -name PowerForensics
]]

-- lua string to bytes conversion
local bytes = { string.byte(psscript, 1,-1) }
-- get a base64 string from the data
psscript_b64 = hunt.base64(bytes)
hunt.log("base64 script: " .. psscript_b64)
-- get the bytes from a base64 string
back_to_string = hunt.unbase64(psscript_b64)
-- print bytes as a string
hunt.log("back to string: " .. hunt.bytes_to_string(back_to_string))
```

```lua
-- GZip a file
temppath = "C:\\windows\\notepad.exe"
outpath = "C:\\windows\\notepad.exe.zip"
hunt.gzip(temppath, outpath, nil)
```

| Function | Description |
| --- | --- |
| **hunt.gzip(from: string, to: string, level: int)** | Compresses `from` into an archive `to`, level is optional (0-9) |
| **hunt.base64(data: bytes)** | Takes a `table` of bytes and returns a base64 encoded `string`. |
| **hunt.unbase64(data: string)** | Takes a base64 encoded `string` and returns a `table` of bytes. |
| **hunt.bytes_to_string(data: bytes)** | Takes a `table` of bytes and returns a `string`. |

#### Network

**Examples:**
```lua
-- list IPs for a domain name
for _, ip in pairs(hunt.net.nslookup("google.com")) do
    -- output: "ip: 172.217.6.46"
    -- output: "ip: 2607:f8b0:4005:804::200e"
    hunt.log("ip: " .. ip)
end
```

```lua
-- list DNS for an IP
for _, dns in pairs(hunt.net.nslookup("8.8.8.8")) do
    -- output: "dns: dns.google"
    hunt.log("dns: " .. dns)
end
```

| Function | Description |
| --- | --- |
| **hunt.net.api()** | Returns a string value of the HUNT instance URL the script is currently attached to. This can be empty if the script is being executed as a test or off-line scan. |
| **hunt.net.api_ipv4()** | Returns a list of IPv4 addresses associated with the HUNT API, this list can be empty if executed under testing or as an off-line scan. |
| **hunt.net.api_ipv6()** | Returns a list of IPv6 addresses associated with the HUNT API, this list can be empty if executed under testing or as an off-line scan; |
| **hunt.net.nslookup(string)** | Returns a list of IP addresses associated with the input item. This will be empty if lookup fails. |
| **hunt.net.nslookup4(string)** | Returns a list of IPv4 addresses associated with the input item. This will be empty if lookup fails. |
| **hunt.net.nslookup6(string)** | Returns a list of IPv6 addresses associated with the input item. This will be empty if lookup fails. |


#### Web
For web requests, you can instantiate a web client to perform http(s) methods. An optional proxy and header field is also available.
The format for using a proxy is `user:password@proxy_address:port`.

**Example:**
```lua
-- Fetch data from a web server
client = hunt.web.new("https://my.domain.org")
-- Use a proxy server
client:proxy("myuser:password@10.11.12.88:8888")
-- Custom header
client:add_header("authorization", "mytokenvalue")

-- Saves response body to a file
client:download_file("./my_data_file.txt")
-- Stores response body in a variable (table of bytes)
data = client:download_data()
-- Stores response body in a string variable
data = client:download_string()
```

| Function | Description |
| --- | --- |
| **get()** | Sets the HTTP request type as GET (default) |
| **post()** | Sets the HTTP request type as POST |
| **enable_tls_verification()** | Enforces TLS certificate validation (default) |
| **disable_tls_verification()** | Disables TLS certificate validation |
| **proxy(config: string)** | Configures the client to use a proxy server |
| **download_data()** | Performs the HTTP request and returns the data as bytes |
| **download_string()** | Performs the HTTP request and returns the data as a string |
| **download_file(path: string)** | Performs the HTTP request and  saves the data to `path` |
| **add_header(name: string, value: string)** | Adds an HTTP header to the client request


#### Process

**Examples:**
```lua
-- List running processes
procs = hunt.process.list()
for _, proc in pairs(procs) do
    hunt.log("Found pid " .. proc:pid() " .. " @ " .. proc:path())
    hunt.log("- Owned by: " .. proc:owner())
    hunt.log("- Started by: " .. proc:ppid())
    hunt.log("- Command Line: " .. proc:cmd_line())
end
```

```lua
-- Kill all "malware.exe" processes
for _, pid in pairs(hunt.process.kill_process("malware.exe")) do
    hunt.log("killed malware.exe running as " .. tostring(pid))
end
```

| Function | Description |
| --- | --- |
| **hunt.process.kill_pid(pid: number)** | Ends the process identified by `pid` |
| **hunt.process.kill_process(name: string)** | Ends any process with `name` |
| **hunt.process.list()** | Returns a list of processes found running |


#### Registry
These registry functions interact with the Native (`Nt*`) Registry APIs and
therefore use Windows kernel's `\Registry\User` style of registry paths. In this
convention there are only two root keys to worry about: `Machine` and `User`.

- HKEY_USERS: `\Registry\User\`
- HKEY_LOCAL_MACHINE (HKLM): `\Registry\Machine\`

`HKEY_CURRENT_USER:\SOFTWARE\MyApp` can be addressed with: `\Registry\User\<user_sid>\SOFTWARE\MyApp`

These functions will return empty values when run on platforms other than Windows.


**Examples:**
```lua
-- list values in a specific HKLM runkey key
key = '\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\iTunesHelper'
for propertyname,value in pairs(hunt.registry.list_values(key)) do
    print(propertyname .. ": " .. value)
end
```

```lua
-- Iterate through each user profile's and list their run keys
-- (includes HKEY_CURRENT_USER and all other HK_USER profiles)
user_sids = hunt.registry.list_keys("\\Registry\\User")
for _,user_sid in pairs(user_sids) do
    key = '\\Registry\\User\\' ..user_sid..'\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    hunt.debug(f"Querying key: ${key}")
    values = hunt.registry.list_values(key)
    if values then
        for property_name,value in pairs(values) do
            hunt.log("Property name: "..property_name..", Value: " .. value)
        end
    end
end
```

| Function | Description |
| --- | --- |
| **hunt.registry.list_keys(path: string)** | Returns a list of registry keys located at `path`. This will be empty on failure. |
| **hunt.registry.list_values(path: string)** | Returns a list of registry property name/value pairs located at `path`. This will be empty on failure. All values are coerced into strings. |

#### Hashing

**Examples:**
```lua
-- Hash a file
hash = hunt.hash.sha1('/bin/bash')
hunt.log(f"/bin/bash: ${hash}")
```

```lua
-- Hash a string
-- (input data must be an "array" of bytes)
some_data = "an important string to hash"
-- convert the string to a table ("array") of bytes
bytes = { string.byte(some_data, 1, -1) }
hash = hunt.hash.sha1_data(bytes)
-- output: "hashed: e70d27cd90d42fdd7674ac965d7d5fa56ca95fdc"
hunt.log(f"hashed: ${hash})
```

| Function | Description |
| --- | --- |
| **hunt.hash.sha256(path: string)** | Returns the string hash of the file |
| **hunt.hash.sha256_data(data)** | Returns the string hash of a data blob |
| **hunt.hash.sha1(path: string)** | Returns the string hash of the file |
| **hunt.hash.sha1_data(data)** | Returns the string hash of a data blob |
| **hunt.hash.md5(path: string)** | Returns the string hash of the file |
| **hunt.hash.md5_data(data)** | Returns the string hash of a data blob |
| **hunt.hash.fuzzy(path: string)** | Returns the string hash of the file |
| **hunt.hash.fuzzy_data(data)** | Returns the string hash of a data blob |

#### Recovery

```lua
-- use s3 upload, with authentication
recovery = hunt.recovery.s3('my_key_id', 'myaccesskey', 'us-east-2', 'my-bucket')
recovery:upload_file('c:\\windows\\system32\\notepad.exe', 'evidence.bin')
```

```lua
-- use s3 upload, without authentication (bucket must be writable without auth)
recovery = hunt.recovery.s3(nil, nil, 'us-east-2', 'my-bucket')
recovery:upload_file('c:\\windows\\system32\\notepad.exe', 'evidence.bin')
```

| Function | Description |
| --- | --- |
| **hunt.recovery.s3(access_key_id: string, secret_access_key: string, region: string, bucket: string)** | S3 recovery client. |
| **upload_file(local: string, remote: string)** | Upload a local file to remote path |


#### Analysis
```lua
-- Create a new autostart 
a = hunt.survey.autostart()

-- Add the location of the executed file
a:exe("/home/user/.zDj289d/.tmp.sh")
-- Add optional parameter information
a:params("--listen 1337")
-- Custom 'autostart type'
a:type("Bash Config")
-- Where the reference was found
a:location("/home/user/.bashrc")

-- Add this information to the collection
hunt.survey.add(a)
```

```lua
-- Create a new artifact 
a = hunt.survey.artifact()

-- Add the location of the executed file
a:exe("/usr/local/bin/nc")
-- Add optional parameter information
a:params("-l -p 1337")
-- Custom 'autostart type'
a:type("Log File Entry")
-- Executed on
a:executed("2019-05-01 11:23:00")
-- Modified on
a:modified("2018-01-01 01:00:00")

-- Add this information to the collection
hunt.survey.add(a)
```

| Function | Description |
| --- | --- |
| **hunt.survey.autostart()** | Create an object to be added to the `autostart` collection |
| **hunt.survey.artifact()** | Create an object to be added to the `artifact` collection |

##### Autostarts
| Function | Description |
| --- | --- |
| **autostart:exe(string)** | Sets the path to the executed file [REQUIRED] |
| **autostart:params(string)** | *Optional:* Sets the parameters of executed file |
| **autostart:type(string)** | Sets the custom *type* of artifact |
| **autostart:location(string)** | Where the autostart was located (config file, registry path, etc) [REQUIRED] |
| **artifact:md5(string)** | *Optional:* Sets md5 for file explicitly, otherwise will attempt to hash file if present |
| **artifact:sha1(string)** | *Optional:* Sets sha1 for file explicitly, otherwise will attempt to hash file if present |
| **artifact:sha256(string)** | *Optional:* Sets sha256 for file explicitly, otherwise will attempt to hash file if present |

##### Artifacts
| Function | Description |
| --- | --- |
| **artifact:exe(string)** | Sets the path to the executed file [REQUIRED] |
| **artifact:params(string)** | *Optional:* Sets the parameters of executed file |
| **artifact:type(string)** | Sets the custom *type* of artifact |
| **artifact:md5(string)** | *Optional:* Sets md5 for file explicitly, otherwise will attempt to hash file if present |
| **artifact:sha1(string)** | *Optional:* Sets sha1 for file explicitly, otherwise will attempt to hash file if present |
| **artifact:sha256(string)** | *Optional:* Sets sha256 for file explicitly, otherwise will attempt to hash file if present |
| **artifact:executed(string)** | *Optional:* Sets *executed on* metadata, must be `2019-11-30 12:11:10` format |
| **artifact:modified(string)** | *Optional:* Sets *modified on* metadata, must be `2019-11-30 12:11:10` format |


##### Yara
```lua
rule = [[
rule is_malware {

  strings:
    $flag = "IAmMalware"

  condition:
    $flag
}
]]

yara = hunt.yara.new()
yara:add_rule(rule)
for _, signature in pairs(yara:scan("c:\\malware\\lives\\here\\bad.exe")) do
    hunt.log("Found " .. signature .. " in file!")
end
```

| Function | Description |
| --- | --- |
| **hunt.yara.new()** | New yara instance. |
| **add_rule(rule: string)** | Add a rule to the yara instance. Once a scan is executed, no more rules can be added. |
| **scan(path: string)** | Scan a file at `path`, returns a list of the rules matched. |

#### Status
The result of an extension can optionally carry a threat status which influences the rest
of the Infocyte HUNT analysis system. Default is unknown.

| Function | Description |
| --- | --- |
| **hunt.status.good()** | Marks the extension output as benign |
| **hunt.status.low_risk()** | Marks the extension output as low risk |
| **hunt.status.suspicious()** | Marks the extension output as suspicious |
| **hunt.status.bad()** | Marks the extension output as bad/malicious |

#### Extras

```lua
-- Convert a string into a table and print it
table = hunt.split("a,b,c",",")
hunt.print_table(table)
```

```lua
-- Will download and start the agent, it will then wait to be "approved"
hunt.install_agent()
-- Using a pre-defined authentication key will automatically be approved
hunt.install_agent("server_key")
```

| Function | Description |
| --- | --- |
| **hunt.split(string: string, delim: string)** | Split a `string` by a delimiter into a `table` |
| **hunt.splitn(string: string, count: int, delim: string)** | Split a `string` `n` times by a delimiter into a `table` |
| **hunt.rsplit(string: string, delim: string)** | Split a `string` by a delimiter into a `table` in reverse |
| **hunt.rsplitn(string: string, count: int, delim: string)** | Split a `string` `n` times by a delimiter into a `table` in reverse |
| **hunt.print_table()** | Prints a lua table (useful for troubleshooting and writing extensions |
| **hunt.sleep(seconds: int)** | Sleep for a number of seconds |
| **hunt.sleep_ms(milliseconds: int)** | Sleep for a number of milliseconds |
| **hunt.install_agent()** | Downloads and configures an agent for the current instance |


### Examples

```lua
hunt.log("My first HUNT extension!")
```

### Contributing
Infocyte welcomes any contributions to this repository. The preferred method is
to
[open a pull request](https://help.github.com/en/articles/about-pull-requests)
with a description of the change. 

If you would like to collaborate on an extension, reach out to Infocyte support and you will be connected to someone that will work with you on it.

### Feature Requests
If there is a feature you would like seen added to the extension system, feel
free to open an issue with a description of the new capability!

### Learn lua
- [LearningLua (Official Tutorial)](http://lua-users.org/wiki/LearningLua)
- [Learn Lua in 15 Minutes](http://tylerneylon.com/a/learn-lua/)
