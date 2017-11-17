#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Recipe:: 1_2_password
#

return unless node['platform_family'] == 'windows'

# Set Account lockout duration to 900 minutes
execute 'CIS 1.2.1 Account lockout duration' do
  command 'net accounts /lockoutduration:900'
  action :run
  not_if { ::File.exist?('C:\actLockoutDur.lock') }
  notifies :create, 'file[C:\actLockoutDur.lock]', :immediately
end

file 'C:\actLockoutDur.lock' do
  action :nothing
end
