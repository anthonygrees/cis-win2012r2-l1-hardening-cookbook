#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 2_3_4_removable_media
#

return unless node['platform_family'] == 'windows'

# 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
# CIS 2.3.4.1
registry_key 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{
    name: 'AllocateDASD',
    type: :dword,
    data: '0'
  }]
  recursive true
  action :create
end
