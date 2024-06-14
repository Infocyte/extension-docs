# Datto EDR Extensions
[Datto EDR](https://www.datto.com/products/datto-edr/) is an Endpoint Detection and Response (EDR) platform. 
In addition to the plethora of native host data collection and analysis provided by default, 
users are able to define their own collections and response actions to be performed on endpoints and servers. 
Here you will find examples and contributed extensions which can be easily loaded
into the Datto EDR platform.

**This repo contains:**
- [Datto EDR Extensions](#datto-edr-extensions)
    - [Overview](#overview)
        - [Collection Extensions](#collection-extensions)
        - [Response Extensions](#response-extensions)
    - [Usage](#usage)
    - [API Reference](#api-reference)
      - [Logging and Output](#logging-and-output)
      - [Date and Time](#date-and-time)
      - [Environmental](#environmental)
      - [Shell Commands](#shell-commands)
      - [File System](#file-system)
      - [Data](#data)
      - [Network](#network)
      - [Web](#web)
      - [Process](#process)
      - [Registry](#registry)
      - [Hashing](#hashing)
      - [Response](#response)
      - [Recovery](#recovery)
      - [Analysis](#analysis)
        - [Add Autostart](#add-autostarts)
        - [Add Artifact](#add-artifacts)
      - [Yara](#yara)
      - [Status](#status)
      - [Miscellaneous](#miscellaneous)
    - [Examples](#examples)
    - [Feature Requests](#feature-requests)
    - [Learn lua](#learn-lua)

## Overview
Our extension system is built on top of [Lua 5.3](https://www.lua.org),
which provides an easy to deploy, cross platform, and feature-rich library of
built-in functions. This includes file system, string , I/O, math, operations
(among others). Refer to the
[Lua Reference Manual](https://www.lua.org/manual/5.3/contents.html) for
detailed documentation on usage or you can click [here](#learn-lua) for Lua
tutorials.

In addition to the Lua standard library, Datto EDR exposes direct function calls 
and capabilities of its' agent that make interacting with the host
operating systems more powerful and convenient. This extended language is the
real engine that powers the extension system. With these enhancements, extension
authors can easily perform web requests, access the windows registry, terminate
running processes, even add items to the existing result set retrieved
by the platform's standard host collection routine. Examples also exist to call
other types of scripts like Powershell, Python or Bash depending on availability
of the relevant interpreter on the host.

There are currently two types of extensions supported: Collection & Response.

##### Collection Extensions
Collection extensions extend what is collected or inspected at scan time. This
can be additional registry keys or files to be analyzed or YARA signatures to be
used on the host-side. Threat statuses can be flagged based on your logic and
text fields are available for arbitrary data collection up to 3MB in size. For
large evidence collection, we will have functions available to push data direct
from the host to a user provided AWS S3 Bucket, sFTP, or SMB share.

##### Response Extensions
Response Extensions cause direct changes to remote systems. These can be
remediation actions like host isolation, malware killing, host hardening
routines (like changing local logging configurations), or other installing
3rd party tools.

## Usage
After logging into your Datto EDR instance (with an administrator role) simply navigate to `Admin->Extensions`.

Datto EDR default extensions are automatically loaded/updated but start in the disabled state.  Enable the 
extensions (by marking it "Active") you wish to use or your can create your own by copying one of the 
default extensions or starting from scratch.

Hitting save on a new or edited extension will perform a syntax validation and if everything checks out, will
save the newly created extension for use. To make the extension available to deploy during a scan, 
make sure you click the `Active` column to enable it as an option.

Once an extension is created and activated, it can be chosen for execution during a scan of a target group.

----
## API Reference

### Logging and Output
These functions provide the only methods to capture output from scripts that are
run. Using standard Lua `print()` or `io.write()` will cause data to be written
to standard output, but not captured and transmitted back to the Datto EDR
platform.

**Example:**
```lua
hunt.log("Hello")
hunt.summary("This is a summary")
```

| Function | Description |
| --- | --- |
| **hunt.log(string)** | Captures the input value and saves it to the extension output object to be viewed later in the Datto EDR console. |
| **hunt.warn(string)** | Writes a string to the `warning` log level of the survey, as well as capture to the script output. |
| **hunt.error(string)** | Writes a string to the `error` log level of the survey, as well as capture to the script output. |
| **hunt.verbose(string)** | Writes a string to the `verbose` log level of the survey, as well as capture to the script output. |
| **hunt.debug(string)** | Writes a string to the `debug` log level of the survey, as well as capture to the script output. |
| **hunt.trace(string)** | Writes a string to the `trace` log level of the survey, as well as capture to the script output. |
| **hunt.summary(string)** | Writes a short string to the `summary` of a response action. Only displayed if extension is ran as an interactive response. |


### Date and Time
These functions provide a method to parse strings into datetime objects, enabling comparisons.
Formats:
- SIMPLE_DATE = "%Y-%m-%d"
- SIMPLE_DATE_TIME = "%Y-%m-%d %H:%M"
- SIMPLE_DATE_TIME_SEC = "%Y-%m-%d %H:%M:%S"
- SIMPLE_DATE_TIME_SEC_TZ = "%Y-%m-%d %H:%M:%S%Z"
- ISO_DATE_TIME_SEC_TZ = "%Y-%m-%dT%H:%M:%S%Z"

**Example:**
```lua
dt = hunt.date.new("2023-1-1")
dt2 = hunt.date.new("2023-1-3")
print(dt)
print(dt2)
print(dt2 > gt)
```

| Function | Description |
| --- | --- |
| **hunt.date.new(date_string)** | Parses a string and returns a datetime object |


### Environmental
Functions to check or access operating system enviroment variables and host information

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
| **hunt.env.tempdir()** | Platform agnostic way to get a temporary directory. Returns a string path. |

### Shell Commands
Functions to execute scripts in other runtime enviroments (shell, powershell, or python)

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
| **hunt.env.run(path, arg1, arg2, ..)** |  Executes an application or utility (exe) with comma seperated parameters. Returns `strings` for stdout and sterr. Accepts an array or comma seperated list of strings as input. |
| **hunt.env.run_powershell(command)** | Executes the provided powershell command (`string`). Returns `string` for stdout and sterr |
| **hunt.env.run_python(command)** | Executes the provided python command (`string`). Returns `string` for stdout and sterr |


### File System
Functions to access the file system directory.

**Examples**
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

| Function | Description |
| --- | --- |
| **hunt.fs.ls(path, [path2], [pathn], [opt])** | Takes one or more paths and returns a list of files. |
| **hunt.fs.path_exists(path)** | Returns a `boolean` if a path exists or not |
| **hunt.fs.ls_stream()** | TBD |
| **hunt.fs.is_file(path)** | Returns a `boolean` if the path is a file (not a directory) |
| **hunt.csv.open(path)** | Opens a CSV file and reads it into a lua `table`. |


### Data
Functions to manipulate files and data.

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

```lua
-- Parse CSV string output
str_csv = hunt.env.run_powershell("get-process | select id, name, path, commandline | convertto-csv -NoTypeInformation")
csv = hunt.csv.parse(str_csv)
hunt.print_table(csv)
```

| Function | Description |
| --- | --- |
| **hunt.gzip(path_from, path_to, level)** | Compresses the file at `path_from` into an archive named `path_to`, `level` is optional number (0-9) representing the gzip strength |
| **hunt.base64(data)** | Takes a `table` of bytes and returns a base64 encoded `string`. |
| **hunt.unbase64(base64_string)** | Takes a base64 encoded `string` and returns a `table` of bytes. |
| **hunt.bytes_to_string(data)** | Takes a `table` of bytes and returns a `string`. |
| **hunt.csv.parse(csv_string)** | Parses a string representation of a csv (such as those returned by powershell) and outputs a group of objects. |  

### Network

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
| **hunt.net.api()** | Returns the url (`string`) of the Datto EDR instance the script is currently attached to. This can be empty if the script is being executed as a test or off-line scan. |
| **hunt.net.instance()** | Returns the name (`string`) of the Datto EDR instance the script is currently attached to. This can be empty if the script is being executed as a test or off-line scan. |
| **hunt.net.api_ipv4()** | Returns a list of IPv4 addresses associated with the Datto EDR API, this list can be empty if executed under testing or as an off-line scan. |
| **hunt.net.api_ipv6()** | Returns a list of IPv6 addresses associated with the Datto EDR API, this list can be empty if executed under testing or as an off-line scan; |
| **hunt.net.nslookup(name:)** | Returns a list of IP addresses associated with the input dns name or dns names if the input is an IP address. This will be empty if lookup fails. |
| **hunt.net.nslookup(ip)** | Returns a list of dns names associated with the input IP address. This will be empty if lookup fails. |
| **hunt.net.nslookup4(name)** | Returns a list of IPv4 addresses associated with the input item. This will be empty if lookup fails. |
| **hunt.net.nslookup6(name)** | Returns a list of IPv6 addresses associated with the input item. This will be empty if lookup fails. |


### Web
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
| **post(data)** | Sets the HTTP request type as POST |
| **enable_tls_verification()** | Enforces TLS certificate validation (default) |
| **disable_tls_verification()** | Disables TLS certificate validation |
| **proxy(url)** | Configures the client to use a proxy server at the provided url |
| **download_data()** | Performs the HTTP request and returns the data as bytes |
| **download_string()** | Performs the HTTP request and returns the data as a string |
| **download_file(path)** | Performs the HTTP request and saves the data to `path` |
| **add_header(name, value)** | Adds an HTTP header to the client request


### Process

**Examples:**
```lua
-- List running processes
procs = hunt.process.list()
for _, proc in pairs(procs) do
    hunt.log("Found pid " .. proc:pid() " .. " @ " .. proc:path())
    hunt.log("- Name: " .. proc:name())
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
| **hunt.process.kill_pid(pid)** | Ends the process identified by `pid` |
| **hunt.process.kill_process(name)** | Ends any process with `name` |
| **hunt.process.list()** | Returns a list of processes found running |
| **hunt.process.get_process(name)** | Look up process by `name` |
| **hunt.process.get_process(pid)** | Look up process by `pid` |


### Registry
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
| **hunt.registry.list_keys(key)** | Returns a list of registry keys located under the key path provided. This will be empty on failure. |
| **hunt.registry.list_values(key)** | Returns a list of registry property name/value pairs located at the provided key path. This will be empty on failure. All values are coerced into strings. |
| **hunt.registry.write_value(key, value_name, value)** | Writes a new string value to the registry key and property name |
| **hunt.registry.delete_key(key)** | Deletes a registry key|
| **hunt.registry.delete_value(key, value_name)** | Deletes a registry value by key path and property name |

### Hashing
Functions to hash data or strings

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


### Response
Functions to respond or isolate the machine

```lua
-- 
iso = hunt.isolator()
for ip, _ in pairs(allowlist) do
    hunt.log(string.format("Committing %s to allow list", ip))
    _, err = iso:allow(ip)
    if err and err ~= '' then
        hunt.error(err)
    end
end
_, err = iso:isolate()
if err and err ~= '' then
    print(err)
    if err:find("0x80320009") then
        hunt.verbose(string.format("%s", err))
        hunt.warn("Host is already isolated")
        hunt.status.good()
        hunt.summary("Already Isolated!")
        return
    else
        hunt.error(string.format("FAILED: %s", err))
        hunt.status.bad()
        hunt.summary("FAILED to Isolate!")
        return
    end
else
    hunt.log("Host Isolation Filter started")
    hunt.summary("Isolated")
end
```

| Function | Description |
| --- | --- |
| **hunt.response.quarantine(path)** | Neuter file by path with XOR encryption or similar. Store locally with metadata appended to file format (header?) |
| **hunt.response.unquarantine(path)** | Unneuter a file that was quarantined and return to where it was |
| **hunt.isolator()** | Create a host isolator |

##### Isolator
| Function | Description |
| --- | --- |
| **isolator:isolate()** | Isolate the host |
| **isolator:restore()** | Unisolate the host |
| **isolator:allow(ip)** | Add an ip address (`string`) to the isolator allowlist |


### Recovery
Functions to upload data to Datto EDR or user provided recovery point.

```lua
-- Upload file to Datto EDR
link = hunt.recovery.upload('c:\\windows\\system32\\notepad.exe')
hunt.log(link)
```

```lua
-- use user provided s3 bucket to upload, with authentication
recovery = hunt.recovery.s3('my_key_id', 'myaccesskey', 'us-east-2', 'my-bucket')
recovery:upload_file('c:\\windows\\system32\\notepad.exe', 'evidence.bin')
```

```lua
-- use user provided s3 bucket to upload, without authentication (bucket must be writable without auth)
recovery = hunt.recovery.s3(nil, nil, 'us-east-2', 'my-bucket')
recovery:upload_file('c:\\windows\\system32\\notepad.exe', 'evidence.bin')
```

| Function | Description |
| --- | --- |
| **hunt.recover.upload(path)** | Upload a local file to Datto EDR provisioned storage. Returns a url link to download the object (deleted after 7 days) |
| **hunt.recovery.s3(access_key_id, secret_access_key, region, bucket_name)** | Creates a user defined S3 recovery client. |
| **hunt.recovery.scp(host, [username], [password], [ssh_key_path], [ssh_key_pass])** | Creates a user defined scp via ssh recovery client. |
| **hunt.recovery.sftp(host, [username], [password], [ssh_key_path], [ssh_key_pass])** | Creates a user defined sftp via ssh recovery client. |
| **hunt.recovery.smb(share, [username], [password])** | Creates a user defined SMB recovery client. WARNING: No Longer Working! |

Recovery object functions:
| Function | Description |
| --- | --- |
| **recovery:upload_file(path, remote_path)** | Upload a local file to a user defined remote path |


### Analysis
Functions to add files to autostart or artifact analysis pipelines

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

##### Add Autostarts
| Function | Description |
| --- | --- |
| **autostart:exe(string)** | Sets the path to the executed file [REQUIRED] |
| **autostart:params(string)** | *Optional:* Sets the parameters of executed file |
| **autostart:type(string)** | Sets the custom *type* of artifact |
| **autostart:location(string)** | Where the autostart was located (config file, registry path, etc) [REQUIRED] |
| **autostart:md5(string)** | *Optional:* Sets md5 for file explicitly, otherwise will attempt to hash file if present |
| **autostart:sha1(string)** | *Optional:* Sets sha1 for file explicitly, otherwise will attempt to hash file if present |
| **autostart:sha256(string)** | *Optional:* Sets sha256 for file explicitly, otherwise will attempt to hash file if present |

##### Add Artifacts
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


### Yara
Functions to perform yara scans

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
| **add_rule(rule)** | Add a rule (`string`) to the yara instance. Once a scan is executed, no more rules can be added. |
| **scan(path)** | Scan a file at `path`, returns a list of the rules matched. |


### Status
The result of an extension can optionally carry a threat status which influences the rest
of the Datto EDR analysis system. Default is unknown.

| Function | Description |
| --- | --- |
| **hunt.status.good()** | Marks the extension output as benign |
| **hunt.status.low_risk()** | Marks the extension output as low risk |
| **hunt.status.suspicious()** | Marks the extension output as suspicious |
| **hunt.status.bad()** | Marks the extension output as bad/malicious |

### Regex
Functions to perform regex matching on strings

```lua
-- Match a string using regex
pattern = "not a (?<str>string)"
str = "this is not a string. It's a better string."
r = hunt.re.new(pattern)
match = r:is_match(str)
print(match)

tbl = r:captures_names(str)
hunt.print_table(tbl)

tbl = r:captures(str)
hunt.print_table(tbl)
```

| Function | Description |
| --- | --- |
| **hunt.re.new(pattern)** | Takes a regex pattern (`string`) and returns a regex object |

| Function | Description |
| --- | --- |
| **re:add(pattern)** | Adds a pattern to the regex object (can have multiple) |
| **re:is_match(string)** | Returns a `boolean` if the loaded regex matches the string |
| **re:captures(string)** | Returns a `table` of matches against the loaded regex patterns |
| **re:captures_names(string)** | Returns a `table` of matching named captures if the regex supports named captures |

### Miscellaneous 
Miscellaneous functions

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
| **hunt.print_table()** | Prints a lua table (useful for troubleshooting and writing extensions |
| **hunt.split(string, delim)** | Split a `string` by a delimiter into a `table` |
| **hunt.splitn(string, n, delim)** | Split a `string` `n` times by a delimiter into a `table` |
| **hunt.rsplit(string, delim)** | Split a `string` by a delimiter into a `table` in reverse |
| **hunt.rsplitn(string, n, delim)** | Split a `string` `n` times by a delimiter into a `table` in reverse |
| **hunt.sleep(seconds)** | Sleep for a number of seconds |
| **hunt.sleep_ms(milliseconds)** | Sleep for a number of milliseconds |


## Examples

```lua
hunt.log("My first Datto EDR extension!")
```

### Feature Requests
If there is a feature you would like seen added to the extension system, feel
free to open an issue with a description of the new capability!

### Learn lua
- [LearningLua (Official Tutorial)](http://lua-users.org/wiki/LearningLua)
- [Learn Lua in 15 Minutes](http://tylerneylon.com/a/learn-lua/)
