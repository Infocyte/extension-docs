--[=[
name: Host Isolation Restore
filetype: Infocyte Extension
type: Response
description: | 
    Reverses the local network isolation of a Windows, Linux, and OSX
    systems using windows firewall, iptables, ipfw, or pf respectively
author: Infocyte
guid: 2896731a-ef52-4569-9669-e9a6d8769e76
created: 2019-9-16
updated: 2021-08-09

# Global variables
globals:

# Runtime arguments
args:

]=]

--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

local verbose = hunt.global.boolean("verbose", false, false)
local test = hunt.global.boolean("test", false, true)

backup_location = "C:\\fwbackup.wfw"
gpo_backup_location = "C:\\fwbackup.key"
iptables_bkup = "/opt/iptables-bkup"

--[=[ SECTION 2: Functions ]=]

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
            hunt.error("[run_cmd] "..out)
            return false, out
        else
            if verbose or test then hunt.log("[run_cmd] "..out) end
            return true, out
        end
    else 
        hunt.error("ERROR: No Output from pipe running command "..cmd)
        return false, "ERROR: No output"
    end
end

--[=[ SECTION 3: Actions ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
osversion = host_info:os()

if string.find(osversion, "windows xp") then
	-- TO DO: XP's netsh firewall

elseif hunt.env.is_windows() then
	if hunt.fs.path_exists(backup_location) then
		-- success, out = run_cmd("netsh advfirewall firewall delete rule name='Infocyte Host Isolation (infocyte)'")
		success, out = run_cmd(f"netsh advfirewall import ${backup_location}")
		os.remove(backup_location)
		-- success, out = run_cmd("netsh advfirewall reset")
		hunt.log("Host has been restored and is no longer isolated")
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end

    -- Backup GPO Firewall Key
    if hunt.fs.path_exists(gpo_backup_location) then
		success, out = run_cmd(f"reg import ${gpo_backup_location}")
		os.remove(gpo_backup_location)
		hunt.log("GPO Firewall Policy Backup has been restored")
	end

    success, out = run_cmd("Netsh advfirewall show allprofiles state")

elseif hunt.env.is_macos() then
	-- TO DO: ipfw (old) or pf (10.6+)

elseif  hunt.env.has_sh() then
	-- Assume linux-type OS and iptables
	if hunt.fs.path_exists(iptables_bkup) then
		hunt.log("Restoring iptables from backup")
		success, out = run_cmd('iptables-restore < '..iptables_bkup)
		os.remove(iptables_bkup)
		

        client = hunt.web.new("https://www.google.com/favicon.ico")
        data, err = client:download_data()
        if not data then
            hunt.error(f"Possible Error. System is still unable to communicate out. Error=${err}")
            hunt.status.suspicious()
            hunt.summary("Restoral Failure")
        else
            hunt.log(f"SUCCESS: System was able to communicate with www.google.com via HTTPS/443")
            hunt.log("Host has been restored and is no longer isolated")
            hunt.status.good()
            hunt.summary("Restored from Backup")
        end
        
	else
		hunt.error("Host has no backup. Cannot be restored (it may not have been isolated).")
	end
end



