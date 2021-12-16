--[=[ 
name: Deploy Utility
filetype: Infocyte Extension
type: Collection
description: |
    Downloads a compiled executable stored within the script as a base64 string.
    Executes it with provided commandline arguments and returns the results from standard out.

    This version of deploy utility has the binary embedded in base64 and won't require
    internet connectivity outside infocyte.

author: Infocyte
guid: 8d5a388d-b966-4063-aaca-24cea620ebc9
created: 2021-07-24
updated: 2021-07-26

# Global Variables
globals:
- deploy_utility_args:
    description: Arguments for the executable. Example='--help'
    type: string
    required: false

- deploy_utility_sha1:
    description: SHA1 of executable for verification and security. Example='2902F0F8F9EBC74440FE45506A142EC0AD001C5D'
    type: string
    required: false

- proxy:
    description: Proxy info. Example='myuser:password@10.11.12.88:8888'
    type: string
    required: false
    
- verbose:
    description: Print verbose information
    type: boolean
    default: false
    required: false

# Runtime Arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])


deploy_utility_args = hunt.global.string("deploy_utility_args", false)
deploy_utility_sha1 = hunt.global.string("deploy_utility_sha1", false)

verbose = hunt.global.boolean("verbose", false, false)
test = hunt.global.boolean("test", false, true)
proxy = hunt.global.string("proxy", false)

-- Change these:
filename = "deploy.exe"
base64_binary = [=[
<replace this line with base64 string>
]=]

--[=[ SECTION 2: Functions ]=]

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end

function run_cmd(cmd)
    --[=[
        Runs a command on the default shell and captures output
        Input:  [string] -- Command
        Output: [boolean] -- success
                [string] -- returned message
    ]=]
    verbose = verbose or true
    if verbose or test then hunt.log("Running command: "..cmd.." 2>&1") end
    local pipe = io.popen(cmd.." 2>&1", "r")
    if pipe then
        local out = pipe:read("*all")
		pipe:close()
		out = out:gsub("^%s*(.-)%s*$", "%1")
        if out:find("failed|error|not recognized as an") then
            hunt.error("[run_cmd]: "..out)
            return false, out
        else
            if verbose or test then hunt.log("[run_cmd]: "..out) end
            return true, out
        end
    else 
        hunt.error("ERROR: No Output from pipe running command "..cmd)
        return false, "ERROR: No output"
    end
end

--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

if not hunt.env.is_windows() then
    hunt.warn(f"Not a compatible operating system for this extension [${host_info:os()}]")
    return
end

-- define temp paths
--tmppath = os.getenv("systemroot").."\\temp\\ic"
infocytepath = os.getenv("APPDATA").."\\infocyte"
tmppath = infocytepath.."\\tools"
binpath = tmppath.."\\"..filename
if not hunt.fs.path_exists(infocytepath) then 
    print(f"Creating directory: ${infocytepath}")
    s, out = run_cmd(f"mkdir ${infocytepath}")
    if out:find("cannot|fail") then
        hunt.error(f"Failed to make infocyte directory:\n${out}")
        return
    end
end
if not hunt.fs.path_exists(tmppath) then 
    print(f"Creating directory: ${tmppath}")
    s, out = run_cmd(f"mkdir ${tmppath}")
    if out:find("cannot|fail") then
        hunt.error(f"Failed to make temp directory:\n${out}")
        return
    end
end

-- Check if we have binary already and validate hash
deploy_utility_sha1 = string.gsub(deploy_utility_sha1:upper(), '-', '')

download = true
if hunt.fs.path_exists(binpath) then
    -- validate hash
    test_sha1 = hunt.hash.sha1(binpath)
    if test_sha1:upper() == deploy_utility_sha1:upper() then
        hunt.log(f"${filename} on disk matches correct hash")
        download = false
    else
        hunt.warn(f"${filename} on disk [${test_sha1}] did not match expected hash: ${deploy_utility_sha1}. Downloading new.")
        os.remove(binpath)
    end
end

if download then
    local file = io.open(f"${tmppath}/temp.txt",'w')
    file:write(base64)
    file:close()
    
    script = f"$Filename = '${binpath}'\n"
    script = script..f"$base64path = '${tmppath}/temp.txt'\n"
    script = script..[=[
    # Embedded amcache parser
    $base64string = Get-Content $base64path -Raw
    [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String($base64string))
    Remove-Item $base64path
    ]=]
    s, err = hunt.env.run_powershell(script)
    os.remove(file)
    -- Check if we have amcacheparser.exe already and validate hash
    if  s and hunt.fs.path_exists(binpath) then
        -- validate hash
        test_sha1 = hunt.hash.sha1(binpath)
        if test_sha1:upper() == deploy_utility_sha1:upper() then
            hunt.log(f"${binpath} written to disk successfully!")
            download = false
        else
            hunt.error(f"${binpath} on disk [${test_sha1}] did not match expected hash: ${deploy_utility_sha1}. Aborting")
            os.remove(binpath)
            return
        end
    end
end


-- Execute 
hunt.log(f"Executing '${binpath} ${deploy_utility_args}'...")
local success, out = run_cmd(f"${binpath} ${deploy_utility_args}")
if not success then
    hunt.error(f"Failed to run ${binpath} ${deploy_utility_args}:\n${out}")
    return
end
hunt.log(out)
hunt.status.good()