#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 2_3_privacy
#

# Disable Windows Store
# registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore' do
#   values [{ name: 'AutoDownload', type: :dword, data: 4 },
#     { name: 'DisableOSUpgrade', type: :dword, data: 1 }]
#   recursive true
#   action :create
# end

# 'Interactive logon: Do not display last user name' is set to 'Enabled'
# CIS 2.3.7.1
registry_key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'DontDisplayLastUserName',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
# CIS 2.3.7.3
registry_key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'InactivityTimeoutSecs',
    type: :dword,
    data: 900
  }]
  recursive true
  action :create
end

# 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
# CIS 2.3.8.1
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
# 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
# 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
# CIS 2.3.9.2, 2.3.9.3, 2.3.9.5
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [ { name: 'requiresecuritysignature', type: :dword, data: 1 },
    { name: 'enablesecuritysignature', type: :dword, data: 1 },
    { name: 'SMBServerNameHardeningLevel', type: :dword, data: 1 }]
  recursive true
  action :create
end
