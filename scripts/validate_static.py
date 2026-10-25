"""Static checks that do not need Xcode. Run from the project root: python3 scripts/validate_static.py"""
from pathlib import Path
import json, plistlib, re, xml.etree.ElementTree as ET
import yaml

root = Path(__file__).resolve().parents[1]
pbx = (root / 'GhostECC.xcodeproj/project.pbxproj').read_text()
object_ids = set(re.findall(r'^([A-F0-9]{24}) =', pbx, re.M))
assert set(re.findall(r'\b[A-F0-9]{24}\b', pbx)) <= object_ids, 'Dangling Xcode object reference'
assert pbx.count('{') == pbx.count('}') and pbx.count('(') == pbx.count(')')
for p in (root / 'GhostECC').rglob('*.swift'):
    assert str(p.relative_to(root / 'GhostECC')) in pbx, 'Missing app source: ' + str(p)
for p in (root / 'Tests').glob('*.swift'):
    assert p.name in pbx, 'Missing test source: ' + p.name
assert 'INFOPLIST_FILE = GhostECC/Info.plist' in pbx
release = [line for line in pbx.splitlines() if 'name = Release' in line and 'INFOPLIST_KEY' in line]
assert release and all('ENABLE_TESTABILITY' not in line for line in release), 'Testability must be Debug-only'
ET.parse(root / 'GhostECC.xcodeproj/xcshareddata/xcschemes/GhostECC.xcscheme')

info = plistlib.loads((root / 'GhostECC/Info.plist').read_bytes())
assert info['CFBundleURLTypes'][0]['CFBundleURLSchemes'] == ['ghost-ecc']
assert info['ITSAppUsesNonExemptEncryption'] is True
privacy = plistlib.loads((root / 'GhostECC/PrivacyInfo.xcprivacy').read_bytes())
assert privacy['NSPrivacyTracking'] is False
for p in (root / 'GhostECC/Assets.xcassets').rglob('Contents.json'):
    json.loads(p.read_text())

api = yaml.safe_load((root / 'docs/openapi.yaml').read_text())
assert api['openapi'] == '3.0.3'
schemas = api['components']['schemas']
def refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == '$ref': assert item.split('/')[-1] in schemas, item
            else: refs(item)
    elif isinstance(value, list):
        for item in value: refs(item)
refs(api)
assert set(api['paths']) == {'/v1/health', '/v1/queues', '/v1/invitations/{senderId}', '/v1/messages/{senderId}', '/v1/fetch', '/v1/ack', '/v1/delete', '/v1/notify'}

source = '\n'.join(p.read_text() for p in (root / 'GhostECC').rglob('*.swift'))
for forbidden in ['UserDefaults', 'FileManager', 'write(to:', 'NSPersistentContainer', 'AVAudioRecorder', 'AVAudioFile', 'RTC', 'UIScreen.main']:
    assert forbidden not in source, 'Unexpected API: ' + forbidden
assert 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly' in source
assert 'kSecAttrSynchronizable as String: false' in source
assert 'config.urlCache = nil' in source
# The relay must never receive a Ghost ID: no GhostID-typed field may appear in relay request types.
relay_source = (root / 'GhostECC/Networking/RelayClient.swift').read_text()
requests = re.findall(r'struct \w+Request: Encodable \{([^}]*)\}', relay_source)
assert len(requests) == 6 and all('GhostID' not in r for r in requests), 'Relay request contains a Ghost ID'
# Wire constants must match the server.
server = (root / 'server/src/relay.js').read_text()
assert "PROTOCOL = 'GHOST-RELAY-v1'" in server and 'static let domain = "GHOST-RELAY-v1"' in relay_source
assert 'maxMessageBytes: 6_000_000' in server and 'maxWireBytes = 6_000_000' in source
assert 'maxFetchQueues: 64' in server and 'maxFetchQueues = 64' in relay_source
entitlements = plistlib.loads((root / 'GhostECC/GhostECC.entitlements').read_bytes())
assert entitlements['aps-environment'] == 'development'
assert 'CODE_SIGN_ENTITLEMENTS = GhostECC/GhostECC.entitlements' in pbx
bundle = re.search(r'PRODUCT_BUNDLE_IDENTIFIER = ([A-Za-z0-9.-]+);', pbx).group(1)
assert f'TOPIC="{bundle}"' in (root / 'server/deploy/install.sh').read_text(), 'install.sh default APNs topic must match the bundle ID'
assert "'notify'" in server and '"notify"' in relay_source
import subprocess, sys
subprocess.run([sys.executable, str(root / 'scripts/l10n.py'), '--check'], check=True)
pair = re.compile(r'^"((?:[^"\\]|\\.)*)" = "((?:[^"\\]|\\.)*)";$')
for table in (root / 'GhostECC/Localization').glob('*.lproj/*.strings'):
    lines = [l for l in table.read_text(encoding='utf-8').splitlines() if l and not l.startswith('/*')]
    assert lines and all(pair.match(l) for l in lines), f'Malformed strings file: {table}'
    if table.name == 'Localizable.strings':
        for l in lines:
            k, v = pair.match(l).groups()
            assert k.count('%@') == v.count('%@'), f'Placeholder mismatch in {table}: {k}'
assert 'PBXVariantGroup' in pbx and '"sr-Latn"' in pbx
assert "'loc-key': locKey" in (root / 'server/src/apns.js').read_text()
print('Xcode references, Info.plist, privacy manifest, OpenAPI paths, persistence rules and client/server constants: passed.')
