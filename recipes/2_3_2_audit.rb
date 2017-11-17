#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 2_3_2_audit

return unless node['platform_family'] == 'windows'

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
# CIS 2.3.2.1
registry_key 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{
    name: 'scenoapplylegacyauditpolicy',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end
