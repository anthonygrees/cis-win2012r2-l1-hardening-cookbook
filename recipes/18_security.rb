#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 18_security
#

# 18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization' do
  values [{
    name: 'NoLockScreenCamera',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization' do
  values [{
    name: 'NoLockScreenSlideshow',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}' do
  values [{
    name: 'DllName',
    type: :dword,
    data: 'C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll' }]
  recursive true
  action :create
end

# 18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'PwdExpirationProtectionEnabled',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'AdmPwdEnabled',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'PasswordComplexity',
    type: :dword,
    data: 4 }]
  recursive true
  action :create
end

# 18.2.4_L1_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'PasswordLength',
    type: :dword,
    data: 15 }]
  recursive true
  action :create
end

# 18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'PasswordLength',
    type: :dword,
    data: 15 }]
  recursive true
  action :create
end

# 18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd' do
  values [{
    name: 'PasswordAgeDays',
    type: :dword,
    data: 30 }]
  recursive true
  action :create
end

# 18.3.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled
#error
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'AutoAdminLogon',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.3.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters' do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2 }]
  recursive true
  action :create
end

# 8.3.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2 }]
  recursive true
  action :create
end

# 18.3.12_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security' do
  values [{
    name: 'WarningLevel',
    type: :dword,
    data: 90 }]
  recursive true
  action :create
end

# 18.3.4_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{
    name: 'EnableICMPRedirect',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.3.6_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters' do
  values [{
    name: 'nonamereleaseondemand',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.3.8_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' do
  values [{
    name: 'SafeDllSearchMode',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.3.9_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' do
  values [{
    name: 'ScreenSaverGracePeriod',
    type: :dword,
    data: 5 }]
  recursive true
  action :create
end

# 18.4.10.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections' do
  values [{
    name: 'NC_AllowNetBridge_NLA',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.4.10.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections' do
  values [{
    name: 'NC_StdDomainUserSetLocation',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.4.13.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares
# Error
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' do
  values [{
    name: '\\\\*\\NETLOGON',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.4.13.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares
# Error
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' do
  values [{
    name: '\\\\*\\SYSVOL',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 8.4.20.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' do
  values [{
    name: 'fMinimizeConnections',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# 18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{
    name: 'LocalAccountTokenFilterPolicy',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

#
registry_key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' do
  values [{
    name: 'UseLogonCredential',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.8.2.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' do
  values [{
    name: 'ProcessCreationIncludeCmdLine_Enabled',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

#  18.8.18.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch' do
  values [{
    name: 'DriverLoadPolicy',
    type: :dword,
    data: 3 }]
  recursive true
  action :create
end

# 18.8.18.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{
    name: 'NoBackgroundPolicy',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# 18.8.18.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{
    name: 'NoGPOListChanges',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'DontDisplayNetworkSelectionUI',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'DontEnumerateConnectedUsers',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'EnumerateLocalUsers',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'DisableLockScreenAppNotifications',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'AllowDomainPINLogon',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

#
#
#
# Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'fAllowUnsolicited',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'fAllowToGetHelp',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc' do
  values [{
    name: 'EnableAuthEpResolution',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI' do
  values [{
    name: 'DisablePasswordReveal',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI' do
  values [{
    name: 'EnumerateAdministrators',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
## ERROR
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application' do
  values [{
    name: 'Retention',
    type: :dword,
    data: "0"
  }]
  recursive true
  action :create
end

# Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768 }]
  recursive true
  action :create
end

# Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
## ERROR
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security' do
  values [{
    name: 'Retention',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 196608 }]
  recursive true
  action :create
end

# Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
## ERROR
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup' do
  values [{
    name: 'Retention',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768 }]
  recursive true
  action :create
end

# Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
## ERROR
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System' do
  values [{
    name: 'Retention',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System' do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768 }]
  recursive true
  action :create
end

#
#
# Ensure_Configure_Windows_SmartScreen_is_set_to_Enabled_Require_approval_from_an_administrator_before_running_downloaded_unknown_software
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System' do
  values [{
    name: 'EnableSmartScreen',
    type: :dword,
    data: 2 }]
  recursive true
  action :create
end

# Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer' do
  values [{
    name: 'NoDataExecutionPrevention',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer' do
  values [{
    name: 'NoHeapTerminationOnCorruption',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{
    name: 'PreXPSP2ShellProtocolBehavior',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System' do
  values [{
    name: 'MSAOptional',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

#
# TERMINAL SERVICES
#
# Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'DisablePasswordSaving',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'fDisableCdm',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'fEncryptRPCTraffic',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'DeleteTempDirsOnExit',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' do
  values [{
    name: 'PerSessionTempDir',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' do
  values [{
    name: 'DisableEnclosureDownload',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Prevent_the_usage_of_SkyDrive_for_file_storage_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SkyDrive' do
  values [{
    name: 'DisableFileSync',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Configure_Default_consent_is_set_to_Enabled_Always_ask_before_sending_data
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent' do
  values [{
    name: 'DefaultConsent',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Configure_Default_consent_is_set_to_Enabled_Always_ask_before_sending_data
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' do
  values [{
    name: 'AutoApproveOSDumps',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer' do
  values [{
    name: 'NoAutoplayfornonVolume',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{
    name: 'NoAutorun',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands
registry_key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' do
  values [{
    name: 'NoDriveTypeAutoRun',
    type: :dword,
    data: 255 }]
  recursive true
  action :create
end

# Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{
    name: 'EnableUserControl',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer' do
  values [{
    name: 'AlwaysInstallElevated',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Allow_Basic_authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{
    name: 'AllowBasic',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Allow_unencrypted_traffic_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{
    name: 'AllowUnencryptedTraffic',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Disallow_Digest_authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client' do
  values [{
    name: 'AllowDigest',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service' do
  values [{
    name: 'DisableRunAs',
    type: :dword,
    data: 1 }]
  recursive true
  action :create
end

# Ensure Automatic Updates is set to Enabled - 18.9.85.1_L1
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' do
  values [{
    name: 'NoAutoUpdate',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure Automatic Updates Scheduled install Day is set to 0 - 18.9.85.2_L1
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' do
  values [{
    name: 'ScheduledInstallDay',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end

# Ensure No Automatic restarts for auto updates is set to Disabled - 18.9.85.3_L1
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' do
  values [{
    name: 'NoAutoRebootWithLoggedOnUsers',
    type: :dword,
    data: 0 }]
  recursive true
  action :create
end
