#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 2_3_accounts
#

return unless node['platform_family'] == 'windows'

# Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
registry_key 'CIS 2.3.1.2' do
  key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
  values [{
    name: 'NoConnectedUser',
    type: :dword,
    data: 3
  }]
  action :create_if_missing
end

# Accounts: Rename guest account
powershell_script 'CIS 2.3.1.6' do
  code 'Rename-LocalUser -Name "Guest" -NewName "Guest-Disabled"'
  only_if 'Get-LocalUser -Name "Guest"'
end

user 'Guest-Disabled' do
  action :nothing
  subscribes :lock, 'powershell_script[CIS 2.3.1.6]'
end

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
registry_key 'CIS 2.3.2.1' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa'
  values [{
    name: 'scenoapplylegacyauditpolicy',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

# 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
registry_key 'CIS 2.3.4.1' do
  key 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
  values [{
    name: 'AllocateDASD',
    type: :string,
    data: 0
  }]
  recursive true
  action :create
end

# 'Interactive logon: Do not display last user name' is set to 'Enabled'
# 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
registry_key 'CIS 2.3.7.1, 2.3.7.3' do
  key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
  values [{
    name: 'DontDisplayLastUserName',
    type: :dword,
    data: 1
  },
    {
      name: 'InactivityTimeoutSecs',
      type: :dword,
      data: 900
    }
  ]
  recursive true
  action :create
end

# Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)
registry_key 'CIS 2.3.7.8' do
  key 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
  values [{
    name: 'ForceUnlockLogon',
    type: :dword,
    data: 1
  }]
  action :create
end

# 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
registry_key 'CIS 2.3.8.1' do
  key 'HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters'
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
registry_key 'CIS 2.3.9.2, 2.3.9.3, 2.3.9.5' do
  key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters'
  values [ {
    name: 'requiresecuritysignature',
    type: :dword,
    data: 1
  },
    {
      name: 'enablesecuritysignature',
      type: :dword,
      data: 1
    },
    {
      name: 'SMBServerNameHardeningLevel',
      type: :dword,
      data: 1
    }]
  recursive true
  action :create
end

# CIS 2.3.11.7 is more stringent, override this from windows-hardening
delete_resource!(:registry_key, 'HKLM\\System\\CurrentControlSet\\Control\\Lsa')

# 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
# 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
# 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM  NTLM'
registry_key 'CIS: 2.3.10.3, 2.3.11.1, 2.3.11.7' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa'
  values [{
    name: 'RestrictAnonymous',
    type: :dword,
    data: 1,
  },
    {
      name: 'UseMachineId',
      type: :dword,
      data: 1,
    },
    {
      name: 'LmCompatibilityLevel',
      type: :dword,
      data: 5,
    }]
  action :create
end

# 'Network access: Named Pipes that can be accessed anonymously'
# 'Network access: Shares that can be accessed anonymously' is set to 'None'
registry_key 'CIS 2.3.10.6, 2.3.10.10' do
  key 'HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters'
  values [{
    name: 'NullSessionPipes',
    type: :dword,
    data: ''
  },
    {
      name: 'NullSessionShares',
      type: :dword,
      data: ''
    }
  ]
  action :create_if_missing
end

# Ensure 'Network access: Remotely accessible registry paths'
registry_key 'CIS 2.3.10.7' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths'
  values [{
    name: 'Machine',
    type: :dword,
    data: 'System\\CurrentControlSet\\Control\\ProductOptions, System\\CurrentControlSet\\Control\\Server Applications, Software\\Microsoft\\Windows NT\\CurrentVersion',
  }]
  action :create_if_missing
end

# Ensure 'Network access: Remotely accessible registry paths and sub-paths'
registry_key 'CIS 2.3.10.8' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths'
  values [{
    name: 'Machine',
    type: :multi_string,
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

# Enable Strong Encryption for Windows Network Sessions on Clients
# Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
registry_key 'CIS 2.3.11.2' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0'
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

# Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
registry_key 'CIS 2.3.11.3' do
  key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\pku2u'
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0,
  }]
  action :create
end

# 'Network Security: Configure encryption types allowed for Kerberos' is set to
# 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'
registry_key 'CIS 2.3.11.4' do
  key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters'
  values [{
    name: 'SupportedEncryptionTypes',
    type: :dword,
    data: 2147483644,
  }]
  recursive true
  action :create_if_missing
end

# 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
# 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
# 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
registry_key 'CIS 2.3.17.1 2.3.17.3 2.3.17.4' do
  key 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
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
