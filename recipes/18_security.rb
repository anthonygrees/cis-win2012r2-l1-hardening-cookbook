#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 18_security
#

# 'Prevent enabling lock screen camera' is set to 'Enabled'
# 'Prevent enabling lock screen slide show' is set to 'Enabled'
registry_key 'CIS 18.1.1.1, 18.1.1.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization'
  values [
    {
      name: 'NoLockScreenCamera',
      type: :dword,
      data: 1 },
    {
      name: 'NoLockScreenSlideshow',
      type: :dword,
      data: 1 },
  ]
  recursive true
  action :create
end

# LAPS AdmPwd GPO Extension / CSE is installed
registry_key 'CIS 18.2.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}'
  values [{
    name: 'DllName',
    type: :dword,
    data: 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll' }]
  recursive true
  action :create
end

# 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'
# 'Enable Local Admin Password Management' is set to 'Enabled'
# 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'
# 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
# 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'
registry_key 'CIS 18.2.2, 18.2.3, 18.2.4, 18.2.5, 18.2.6' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
  values [
    {
      name: 'PwdExpirationProtectionEnabled',
      type: :dword,
      data: 1 },
    {
      name: 'AdmPwdEnabled',
      type: :dword,
      data: 1 },
    {
      name: 'PasswordComplexity',
      type: :dword,
      data: 4 },
    {
      name: 'PasswordLength',
      type: :dword,
      data: 15 },
    {
      name: 'PasswordAgeDays',
      type: :dword,
      data: 30 },
  ]
  recursive true
  action :create
end

# 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
# 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
registry_key 'CIS 18.3.1, 18.3.9' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  values [
    {
      name: 'AutoAdminLogon',
      type: :dword,
      data: 0 },
    {
      name: 'ScreenSaverGracePeriod',
      type: :dword,
      data: 5 },
  ]
  recursive true
  action :create
end

# 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
registry_key 'CIS 18.3.2' do
  key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters'
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2 }]
  recursive true
  action :create
end

# 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
# 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
registry_key 'CIS 18.3.3, 18.3.4' do
  key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters'
  values [
    {
      name: 'DisableIPSourceRouting',
      type: :dword,
      data: 2 },
    {
      name: 'EnableICMPRedirect',
      type: :dword,
      data: 0 },
  ]
  recursive true
  action :create
end

# 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
registry_key 'CIS 18.3.6' do
  key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters'
  values [{
    name: 'nonamereleaseondemand',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
registry_key 'CIS 18.3.8' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'
  values [{
    name: 'SafeDllSearchMode',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
registry_key 'CIS 18.3.12' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
  values [{
    name: 'WarningLevel',
    type: :dword,
    data: 90 }]
  recursive true
  action :create
end

# 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
# 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
registry_key 'CIS 18.4.10.2, 18.4.10.3' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
  values [
    {
      name: 'NC_AllowNetBridge_NLA',
      type: :dword,
      data: 0 },
    {
      name: 'NC_StdDomainUserSetLocation',
      type: :dword,
      data: 1 }]
  recursive true
  action :create
end

# 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'
registry_key 'CIS 18.4.13.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
  values [
    {
      name: '\\\\*\\NETLOGON',
      type: :dword,
      data: 0 },
    {
      name: '\\\\*\\SYSVOL',
      type: :dword,
      data: 0 }]
  recursive true
  action :create
end

# 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
registry_key 'CIS 18.4.20.1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
  values [{
    name: 'fMinimizeConnections',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'WDigest Authentication' is set to 'Disabled'
registry_key 'CIS 18.6.2' do
  key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
  values [{
    name: 'UseLogonCredential',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 'Include command line in process creation events' is set to 'Disabled'
registry_key 'CIS 18.8.2.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  values [{
    name: 'ProcessCreationIncludeCmdLine_Enabled',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
registry_key 'CIS 18.8.11.1' do
  key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch'
  values [{
    name: 'DriverLoadPolicy',
    type: :dword,
    data: 3 }]
  recursive true
  action :create
end

# 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
# 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
registry_key 'CIS 18.8.18.2, 18.8.18.3' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
  values [
    {
      name: 'NoBackgroundPolicy',
      type: :dword,
      data: 0 },
    {
      name: 'NoGPOListChanges',
      type: :dword,
      data: 0 }]
  recursive true
  action :create
end

# 'Do not display network selection UI' is set to 'Enabled'
# 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'
# 'Enumerate local users on domain-joined computers' is set to 'Disabled'
# 'Turn off app notifications on the lock screen' is set to 'Enabled'
# 'Turn on convenience PIN sign-in' is set to 'Disabled'
# 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'
registry_key 'CIS 18.8.24.1, 18.8.24.2, 18.8.24.3, 18.8.24.4, 18.8.24.5, 18.9.28.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
  values [
    {
      name: 'DontDisplayNetworkSelectionUI',
      type: :dword,
      data: 1 },
    {
      name: 'DontEnumerateConnectedUsers',
      type: :dword,
      data: 1 },
    {
      name: 'EnumerateLocalUsers',
      type: :dword,
      data: 0 },
    {
      name: 'DisableLockScreenAppNotifications',
      type: :dword,
      data: 1 },
    {
      name: 'AllowDomainPINLogon',
      type: :dword,
      data: 0 },
    {
      name: 'EnableSmartScreen',
      type: :dword,
      data: 2 },
  ]
  recursive true
  action :create
end

# 'Configure Offer Remote Assistance' is set to 'Disabled'
# 'Configure Solicited Remote Assistance' is set to 'Disabled'
# 'Do not allow passwords to be saved' is set to 'Enabled'
# 'Do not allow drive redirection' is set to 'Enabled'
# 'Require secure RPC communication' is set to 'Enabled'
# 'Do not delete temp folders upon exit' is set to 'Disabled'
# 'Do not use temporary folders per session' is set to 'Disabled'
registry_key 'CIS 18.8.30.1, 18.8.30.2, 18.9.48.2, 18.9.48.3.3.2, 18.9.48.3.9.2, 18.9.48.3.11.1, 18.9.48.3.11.2' do
  key 'HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services'
  values [
    {
      name: 'fAllowUnsolicited',
      type: :dword,
      data: 0 },
    {
      name: 'fAllowToGetHelp',
      type: :dword,
      data: 0 },
    {
      name: 'DisablePasswordSaving',
      type: :dword,
      data: 1 },
    {
      name: 'fDisableCdm',
      type: :dword,
      data: 1 },
    {
      name: 'fEncryptRPCTraffic',
      type: :dword,
      data: 1 },
    {
      name: 'DeleteTempDirsOnExit',
      type: :dword,
      data: 1 },
    {
      name: 'PerSessionTempDir',
      type: :dword,
      data: 1 }]
  recursive true
  action :create
end

# 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
registry_key 'CIS 18.8.31.1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc'
  values [{
    name: 'EnableAuthEpResolution',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Allow Microsoft accounts to be optional' is set to 'Enabled'
registry_key 'CIS 18.9.6.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  values [{
    name: 'MSAOptional',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
# 'Turn off Autoplay' is set to 'Enabled: All drives'
# 'Turn off shell protocol protected mode' is set to 'Disabled'
registry_key 'CIS 18.9.8.2, 18.9.8.3, 18.9.28.5' do
  key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
  values [
    {
      name: 'NoAutorun',
      type: :dword,
      data: 1 },
    {
      name: 'NoDriveTypeAutoRun',
      type: :dword,
      data: 255 },
    {
      name: 'PreXPSP2ShellProtocolBehavior',
      type: :dword,
      data: 0 }]
  recursive true
  action :create
end

# 'Do not display the password reveal button' is set to 'Enabled'
registry_key 'CIS 18.9.13.1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
  values [{
    name: 'DisablePasswordReveal',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Enumerate administrator accounts on elevation' is set to 'Disabled'
registry_key 'CIS 18.9.13.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
  values [{
    name: 'EnumerateAdministrators',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
# 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
registry_key 'CIS 18.9.24.1.1, 18.9.24.1.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application'
  values [
    {
      name: 'Retention',
      type: :string,
      data: '0',
    },
    {
      name: 'MaxSize',
      type: :dword,
      data: 32768 }]
  recursive true
  action :create
end

# 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
# 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
registry_key 'CIS 18.9.24.2.1, 18.9.24.2.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security'
  values [
    {
      name: 'Retention',
      type: :string,
      data: '0' },
    {
      name: 'MaxSize',
      type: :dword,
      data: 196608 }]
  recursive true
  action :create
end

# 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
# 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
registry_key 'CIS 18.9.24.3.1, 18.9.24.3.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup'
  values [
    {
      name: 'Retention',
      type: :string,
      data: '0' },
    {
      name: 'MaxSize',
      type: :dword,
      data: 32768 }]
  recursive true
  action :create
end

# 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
# 'Turn off heap termination on corruption' is set to 'Disabled'
# 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
registry_key 'CIS 18.9.28.3, 18.9.28.4, 18.9.8.1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer'
  values [
    {
      name: 'NoDataExecutionPrevention',
      type: :dword,
      data: 0 },
    {
      name: 'NoHeapTerminationOnCorruption',
      type: :dword,
      data: 0 },
    {
      name: 'NoAutoplayfornonVolume',
      type: :dword,
      data: 1 }]
  recursive true
  action :create
end

# 'Prevent downloading of enclosures' is set to 'Enabled'
registry_key 'CIS 18.9.49.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
  values [{
    name: 'DisableEnclosureDownload',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Prevent the usage of SkyDrive for file storage' is set to 'Enabled'
registry_key 'CIS 18.9.54.1' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive'
  values [{
    name: 'DisableFileSync',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Configure Default consent' is set to 'Enabled: Always ask before sending data'
registry_key 'CIS 18.9.67.2.1' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent'
  values [{
    name: 'DefaultConsent',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'
registry_key 'CIS 18.9.67.3' do
  key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
  values [{
    name: 'AutoApproveOSDumps',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 'Allow user control over installs' is set to 'Disabled'
# 'Always install with elevated privileges' is set to 'Disabled'
registry_key 'CIS 18.9.69.1, 18.9.69.2' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer'
  values [
    {
      name: 'EnableUserControl',
      type: :dword,
      data: 0 },
    {
      name: 'AlwaysInstallElevated',
      type: :dword,
      data: 0 }]
  recursive true
  action :create
end

# 'Allow Basic authentication' is set to 'Disabled'
# 'Allow unencrypted traffic' is set to 'Disabled'
# 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
registry_key 'CIS 18.9.81.1.1, 18.9.81.1.2, 18.9.81.2.3' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
  values [
    {
      name: 'AllowBasic',
      type: :dword,
      data: 0 },
    {
      name: 'AllowUnencryptedTraffic',
      type: :dword,
      data: 0 },
    {
      name: 'DisableRunAs',
      type: :dword,
      data: 1 },
  ]
  recursive true
  action :create
end

# 'Disallow Digest authentication' is set to 'Enabled'
registry_key 'CIS 18.9.81.1.3' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client'
  values [{
    name: 'AllowDigest',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 'Configure Automatic Updates' is set to 'Enabled'
# 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
# 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
registry_key 'CIS 18.9.85.1, 18.9.85.2, 18.9.85.3' do
  key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
  values [
    {
      name: 'NoAutoUpdate',
      type: :dword,
      data: 0 },
    {
      name: 'ScheduledInstallDay',
      type: :dword,
      data: 0 },
    {
      name: 'NoAutoRebootWithLoggedOnUsers',
      type: :dword,
      data: 0 }]
  recursive true
  action :create
end
