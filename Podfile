platform :ios, '17.0'
use_frameworks!
project 'GhostECC.xcodeproj'

target 'GhostECC' do
  pod 'LibSignalClient', :path => 'vendor/libsignal'
  target 'GhostECCTests' do
    inherit! :search_paths
  end
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['SWIFT_ENABLE_EXPLICIT_MODULES'] = 'NO'
      config.build_settings['ENABLE_USER_SCRIPT_SANDBOXING'] = 'NO'
    end
  end
end
