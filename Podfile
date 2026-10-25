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
      # Simulator builds are Apple silicon (arm64) only, so the app and libsignal always match.
      config.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
      config.build_settings['OTHER_LDFLAGS'] = ['$(inherited)', '-lc++'] if target.name == 'LibSignalClient'
    end
  end
  installer.aggregate_targets.each do |aggregate|
    aggregate.user_project.native_targets.each do |target|
      target.build_configurations.each do |config|
        config.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'x86_64'
      end
    end
    aggregate.user_project.save
  end
end
