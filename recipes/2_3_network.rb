#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 2_3_network
#

return unless node['platform_family'] == 'windows'

# Configure 'Network access: Named Pipes that can be accessed anonymously'
# CIS 2.3.10.6
registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{
    name: 'NullSessionPipes',
    type: :multi_string,
    data: %w(LSARPC NETLOGON SAMR),
  }]
  action :create_if_missing
end

# Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM  NTLM'# Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
# Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
# windows-baseline: windows-base-103
# CIS: 2.3.10.3
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 5,
    },
    {
      name: 'RestrictAnonymous',
      type: :dword,
      data: 1,
    },
    {
      name: 'UseMachineId',
      type: :dword,
      data: 1,
    }]
  action :create
end

# Enable Strong Encryption for Windows Network Sessions on Clients
# Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
# windows-baseline: windows-base-201
# CIS 2.3.11.2
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{
    name: 'NtlmMinClientSec',
    type: :dword,
    data: 537_395_200,
    },
    {
      name: 'allownullsessionfallback',
      type: :dword,
      data: 0,
    }]
  action :create
end

if node['windows_hardening']['smbv1']['disable'] == true
  registry_key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
    values [{
      name: 'SMB1',
      type: :dword,
      data: 0
    }]
    action :create_if_missing
  end
end

# Anonymous Access to Windows Shares and Named Pipes is Disallowed
# windows-baseline: windows-base-102

# Ensure 'Accounts: Administrator account status' is set to 'Disabled'
# Users with uid =~ /S\-1\-5\-21\-\d+\-\d+\-\d+\-500/ should be disabled

# Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
# CIS 2.3.1.2
registry_key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'NoConnectedUser',
    type: :dword,
    data: 3
  }]
  action :create_if_missing
end

# Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
# CIS 2.3.7.8
registry_key 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'ForceUnlockLogon',
    type: :dword,
    data: 1
  }]
  action :create_if_missing
end

# Ensure 'Network access: Remotely accessible registry paths'
# CIS 2.3.10.7
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths' do
  values [{
    name: 'Machine',
    type: :dword,
    data: ['System\\CurrentControlSet\\Control\\ProductOptions',
           'System\\CurrentControlSet\\Control\\Server Applications',
           'Software\\Microsoft\\Windows NT\\CurrentVersion'],
  }]
  action :create_if_missing
end

# Ensure 'Network access: Remotely accessible registry paths and sub-paths'
# CIS 2.3.10.8
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths' do
  values [{
    name: 'Machine',
    type: :dword,
    data: ['System\\CurrentControlSet\\Control\\Print\\Printers',
           'System\\CurrentControlSet\\Services\\Eventlog',
           'Software\\Microsoft\\OLAP Server',
           'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print',
           'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
           'System\\CurrentControlSet\\Control\\ContentIndex',
           'System\\CurrentControlSet\\Control\\Terminal Server',
           'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig',
           'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration',
           'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib',
           'System\\CurrentControlSet\\Services\\SysmonLog',
           'System\\CurrentControlSet\\Services\\CertSvc',
           'System\\CurrentControlSet\\Services\\WINS'],
  }]
  action :create_if_missing
end

# Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
# CIS 2.3.11.3
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\pku2u' do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0,
  }]
  action :create
end

# Ensure 'Network Security: Configure encryption types allowed for Kerberos' is
# set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
# CIS 2.3.11.4
registry_key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 2147483644,
  }]
  recursive true
  action :create_if_missing
end

# Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
# Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
# Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
# CIS 2.3.17.1 2.3.17.3 2.3.17.4
registry_key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{
    name: 'FilterAdministratorToken',
    type: :dword,
    data: 1,
  },
          {
            name: 'ConsentPromptBehaviorAdmin',
            type: :dword,
            data: 2,
          },
          {
            name: 'ConsentPromptBehaviorUser',
            type: :dword,
            data: 0,
          }]
  action :create
end
