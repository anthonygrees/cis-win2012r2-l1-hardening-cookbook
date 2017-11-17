#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 9_firewall
#

return unless node['platform_family'] == 'windows'

# Windows Firewall: Domain: Firewall state' is set to 'On (recommended)
# Windows Firewall: Domain: Inbound connections' is set to 'Block (default)
# Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)
# Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
# Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)
# Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)
registry_key 'CIS: 9.1.1, 9.1.2, 9.1.3, 9.1.4, 9.1.5, 9.1.6' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile'
  values [{
    name: 'EnableFirewall',
    type: :dword,
    data: 1,
  },
    {
      name: 'DefaultInboundAction',
      type: :dword,
      data: 1,
    },
    {
      name: 'DefaultOutboundAction',
      type: :dword,
      data: 0,
    },
    {
      name: 'DisableNotifications',
      type: :dword,
      data: 1,
    },
    {
      name: 'AllowLocalPolicyMerge',
      type: :dword,
      data: 1,
    },
    {
      name: 'AllowLocalIPsecPolicyMerge',
      type: :dword,
      data: 1,
    },
  ]
  recursive true
  action :create_if_missing
end

# Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log
# Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater
# Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes
# Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
registry_key 'CIS: 9.1.7, 9.1.8, 9.1.9, 9.1.10' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging'
  values [{
    name: 'LogFilePath',
    type: :string,
    data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log',
  },
    {
      name: 'LogFileSize',
      type: :dword,
      data: 16384,
    },
    {
      name: 'LogDroppedPackets',
      type: :dword,
      data: 1,
    },
    {
      name: 'LogSuccessfulConnections',
      type: :dword,
      data: 1,
    },

  ]
  recursive true
  action :create_if_missing
end

# Windows Firewall: Private: Firewall state is set to 'On (recommended)'
# Windows Firewall: Private: Inbound connections is set to 'Block (default)'
# Windows Firewall: Private: Outbound connections is set to 'Allow (default)'
# Windows Firewall: Private: Settings: Display a notification' is set to 'No'
# Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
# Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
registry_key 'CIS: 9.2.1, 9.2.2, 9.2.3, 9.2.4, 9.2.5, 9.2.6' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile'
  values [
    {
      name: 'EnableFirewall',
      type: :dword,
      data: 1,
    },
    {
      name: 'DefaultInboundAction',
      type: :dword,
      data: 1,
    },
    {
      name: 'DefaultOutboundAction',
      type: :dword,
      data: 0,
    },
    {
      name: 'DisableNotifications',
      type: :dword,
      data: 1,
    },
    {
      name: 'AllowLocalPolicyMerge',
      type: :dword,
      data: 1,
    },
    {
      name: 'AllowLocalIPsecPolicyMerge',
      type: :dword,
      data: 1,
    }
  ]
  recursive true
  action :create_if_missing
end

# 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
# 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
# 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
# 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
registry_key 'CIS: 9.2.7, 9.2.8, 9.2.9, 9.2.10' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging'
  values [
    {
      name: 'LogFilePath',
      type: :string,
      data: '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log',
    },
    {
      name: 'LogFileSize',
      type: :dword,
      data: 16384,
    },
    {
      name: 'LogDroppedPackets',
      type: :dword,
      data: 1,
    },
    {
      name: 'LogSuccessfulConnections',
      type: :dword,
      data: 1,
    }
  ]
  recursive true
  action :create_if_missing
end

# Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
# Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
# Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
# Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'
# Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
# Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
registry_key 'CIS: 9.3.1, 9.3.2, 9.3.3, 9.3.4, 9.3.5, 9.3.6' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile'
  values [
    {
      name: 'EnableFirewall',
      type: :dword,
      data: 1,
    },
    {
      name: 'DefaultInboundAction',
      type: :dword,
      data: 1,
    },
    {
      name: 'DefaultOutboundAction',
      type: :dword,
      data: 0,
    },
    {
      name: 'DisableNotifications',
      type: :dword,
      data: 0,
    },
    {
      name: 'AllowLocalPolicyMerge',
      type: :dword,
      data: 0,
    },
    {
      name: 'AllowLocalIPsecPolicyMerge',
      type: :dword,
      data: 0,
    }
  ]
  recursive true
  action :create_if_missing
end

# Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
# Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
# Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
# Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
registry_key 'CIS: 9.3.7, 9.3.8, 9.3.9, 9.3.10' do
  key 'HKLM\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging'
  values [
    {
      name: 'LogFilePath',
      type: :string,
      data: '%systemroot%\\system32\\logfiles\\firewall\\publicfw.log',
    },
    {
      name: 'LogFileSize',
      type: :dword,
      data: 16384,
    },
    {
      name: 'LogDroppedPackets',
      type: :dword,
      data: 1,
    },
    {
      name: 'LogSuccessfulConnections',
      type: :dword,
      data: 1,
    },
  ]
  recursive true
  action :create_if_missing
end
