name 'cis-win2012r2-l1-hardening'
maintainer 'Matt Ray'
maintainer_email 'matt@chef.io'
license 'Apache-2.0'
description 'CIS Hardening cookbook for Windows 2012 R2'
long_description 'Remediates issues identified by the cis-windows2012r2-level1-memberserver profile'
version '0.1.0'
source_url 'https://github.com/mattray/cis-win2012r2-l1-hardening-cookbook' if respond_to?(:source_url)
issues_url 'https://github.com/mattray/cis-win2012r2-l1-hardening-cookbook' if respond_to?(:issues_url)
chef_version '>= 12.5' if respond_to?(:chef_version)
supports 'windows'

depends 'windows-security-policy'
depends 'windows-hardening'
