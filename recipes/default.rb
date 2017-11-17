#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: default

return unless node['platform_family'] == 'windows'

include_recipe 'windows-hardening::default'

include_recipe 'cis-win2012r2-l1-hardening::1_2_password'
include_recipe 'cis-win2012r2-l1-hardening::2_3_2_audit'
include_recipe 'cis-win2012r2-l1-hardening::2_3_4_removable_media'
include_recipe 'cis-win2012r2-l1-hardening::2_3_network'
include_recipe 'cis-win2012r2-l1-hardening::2_3_privacy'
include_recipe 'cis-win2012r2-l1-hardening::9_firewall'
