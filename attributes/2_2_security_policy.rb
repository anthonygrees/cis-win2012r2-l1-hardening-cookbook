# encoding: utf-8
#
# Cookbook Name:: cis-win2012r2-l1-hardening
# Attributes:: 2_2_security_policy
#

# CIS 2.2.18 'Deny log on as a batch job' to include 'Guests'
default['security_policy']['rights']['SeDenyBatchLogonRight']             = '*S-1-5-32-546'
# CIS 2.2.19 'Deny log on as a service' to include 'Guests'
default['security_policy']['rights']['SeDenyServiceLogonRight']           = '*S-1-5-32-546'
# CIS 2.2.20 'Deny log on locally' to include 'Guests'
default['security_policy']['rights']['SeDenyInteractiveLogonRight']       = '*S-1-5-32-546'
# CIS 2.2.21 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
default['security_policy']['rights']['SeDenyRemoteInteractiveLogonRight'] = '*S-1-5-32-546, *S-1-5-113'
#
# Added to allow WinRM access to scan
default['security_policy']['rights']['SeRemoteInteractiveLogonRight']     = '*S-1-1-0, *S-1-5-32-544, *S-1-5-32-545, *S-1-5-32-551'
default['security_policy']['rights']['SeNetworkLogonRight']               = '*S-1-1-0, *S-1-5-32-544, *S-1-5-32-545, *S-1-5-32-551'