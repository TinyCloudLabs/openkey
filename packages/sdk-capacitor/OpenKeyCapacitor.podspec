require 'json'

Pod::Spec.new do |s|
  s.name = 'OpenKeyCapacitor'
  s.version = JSON.parse(File.read(File.join(__dir__, 'package.json')))['version']
  s.summary = 'OpenKey native authentication and secure storage for Capacitor'
  s.homepage = 'https://github.com/TinyCloudLabs/openkey'
  s.license = 'SEE LICENSE IN LICENSE.md'
  s.author = 'OpenKey'
  s.source = { :git => 'https://github.com/TinyCloudLabs/openkey.git', :tag => s.version.to_s }
  s.source_files = 'ios/Sources/OpenKeyCapacitor/**/*.{swift,h,m}'
  s.ios.deployment_target = '15.0'
  s.dependency 'Capacitor'
  s.swift_version = '5.9'
end
