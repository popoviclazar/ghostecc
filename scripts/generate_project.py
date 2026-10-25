from pathlib import Path
import json, plistlib
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
objects = {}
serial = 0

def put(body):
    global serial
    serial += 1
    key = f'{serial:024X}'
    objects[key] = body
    return key

def update(key, body): objects[key] = body

def ref(path, kind): return put(f'isa = PBXFileReference; lastKnownFileType = {kind}; path = "{path}"; sourceTree = "<group>";')
def build(file): return put(f'isa = PBXBuildFile; fileRef = {file};')
def phase(kind, files): return put(f'isa = {kind}; buildActionMask = 2147483647; files = ({", ".join(files)}); runOnlyForDeploymentPostprocessing = 0;')
def group(name, children, ispath=True): return put(f'isa = PBXGroup; children = ({", ".join(children)}); {"path" if ispath else "name"} = "{name}"; sourceTree = "<group>";')
def config(name, settings): return put(f'isa = XCBuildConfiguration; buildSettings = {{ {settings} }}; name = {name};')
def config_list(settings, debug_extra=''):
    return put(f'isa = XCConfigurationList; buildConfigurations = ({config("Debug", settings + debug_extra + " SWIFT_OPTIMIZATION_LEVEL = \\\"-Onone\\\";" )}, {config("Release", settings)}); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
# Fix quoting after generation; no shell expansions are used.
assets = ROOT / 'GhostECC/Assets.xcassets'
(assets/'AppIcon.appiconset').mkdir(parents=True, exist_ok=True)
(assets/'AccentColor.colorset').mkdir(exist_ok=True)
(assets/'LaunchBackground.colorset').mkdir(exist_ok=True)
(assets/'LaunchBackground.colorset/Contents.json').write_text(json.dumps({'colors':[{'idiom':'universal','color':{'color-space':'srgb','components':{'red':'0.025','green':'0.040','blue':'0.075','alpha':'1.000'}}}],'info':{'author':'xcode','version':1}},indent=2))
(assets/'Contents.json').write_text(json.dumps({'info':{'author':'xcode','version':1}},indent=2))
(assets/'AppIcon.appiconset/Contents.json').write_text(json.dumps({'images':[{'filename':'GhostIcon.png','idiom':'universal','platform':'ios','size':'1024x1024'}],'info':{'author':'xcode','version':1}},indent=2))
(assets/'AccentColor.colorset/Contents.json').write_text(json.dumps({'colors':[{'idiom':'universal','color':{'color-space':'srgb','components':{'red':'0.200','green':'0.480','blue':'1.000','alpha':'1.000'}}}],'info':{'author':'xcode','version':1}},indent=2))
# Rasterize the programmatic ghost mark (no third-party artwork): radial navy background, soft blue glow, gradient ghost.
from PIL import ImageFilter
size = 1024
big = Image.radial_gradient('L').resize((1536, 1536))
falloff = big.crop((256, 338, 256 + size, 338 + size))          # light centre slightly above the middle
image = Image.composite(Image.new('RGB', (size, size), (4, 7, 15)), Image.new('RGB', (size, size), (24, 48, 104)), falloff)
mask = Image.new('L',(size,size),0); draw=ImageDraw.Draw(mask)
draw.ellipse((258,188,766,696),fill=255)
draw.rectangle((258,442,766,806),fill=255)
draw.polygon([(258,806),(343,704),(427,806),(512,704),(597,806),(681,704),(766,806)],fill=255)
# Carve alternating scallops matching the SwiftUI path.
for a,b,c in [(258,343,427),(427,512,597),(597,681,766)]:
    draw.polygon([(a,806),(b,704),(c,806)],fill=0)
glow = mask.filter(ImageFilter.GaussianBlur(64)).point(lambda v: int(v * 0.8))
image.paste(Image.new('RGB', (size, size), (52, 112, 255)), (0, 0), glow)
colour=Image.new('RGB',(size,size)); pixels=colour.load()
for y in range(size):
    t=max(0,min(1,(y-188)/620))
    row=(int(248*(1-t)+56*t),int(251*(1-t)+124*t),255)
    for x in range(size):pixels[x,y]=row
image.paste(colour,(0,0),mask)
face=ImageDraw.Draw(image)
face.rounded_rectangle((414,427,464,511),radius=25,fill=(8,14,30))
face.rounded_rectangle((560,427,610,511),radius=25,fill=(8,14,30))
image.save(assets/'AppIcon.appiconset/GhostIcon.png')
# No account or user ID exists any more: the relay only sees random per-conversation queue IDs and E2E ciphertext.
# Re-check against Apple's App Privacy definitions before submission (see SECURITY.md).
privacy={'NSPrivacyTracking':False,'NSPrivacyTrackingDomains':[],
         'NSPrivacyCollectedDataTypes':[],
         'NSPrivacyAccessedAPITypes':[{'NSPrivacyAccessedAPIType':'NSPrivacyAccessedAPICategorySystemBootTime','NSPrivacyAccessedAPITypeReasons':['35F9.1']}]}
(ROOT/'GhostECC/PrivacyInfo.xcprivacy').write_bytes(plistlib.dumps(privacy))
app_sources=[]; app_children=[]
for p in sorted((ROOT/'GhostECC').rglob('*.swift')):
    reference=ref(str(p.relative_to(ROOT/'GhostECC')),'sourcecode.swift'); app_children.append(reference); app_sources.append(build(reference))
asset_ref=ref('Assets.xcassets','folder.assetcatalog'); privacy_ref=ref('PrivacyInfo.xcprivacy','text.xml')
# Info.plist is merged with the generated keys via INFOPLIST_FILE; it must not be a bundle resource.
info_ref=ref('Info.plist','text.plist.xml')
# Entitlements (push) are referenced by CODE_SIGN_ENTITLEMENTS, not copied into the bundle.
entitlements_ref=ref('GhostECC.entitlements','text.plist.entitlements')
app_children += [asset_ref,privacy_ref,info_ref,entitlements_ref]
# Localization: English plus identity tables for the Serbian-family languages (see scripts/l10n.py).
LANGS=['en','sr-Latn','sr','hr','bs']
def variant(name, langs):
    kids=[put(f'isa = PBXFileReference; lastKnownFileType = text.plist.strings; name = "{l}"; path = "Localization/{l}.lproj/{name}"; sourceTree = "<group>";') for l in langs]
    return put(f'isa = PBXVariantGroup; children = ({", ".join(kids)}); name = "{name}"; sourceTree = "<group>";')
localizable_ref=variant('Localizable.strings',LANGS); infoplist_strings_ref=variant('InfoPlist.strings',['en'])
app_children += [localizable_ref,infoplist_strings_ref]
app_group=group('GhostECC',app_children)
test_sources=[];test_children=[]
for p in sorted((ROOT/'Tests').glob('*.swift')):
    reference=ref(p.name,'sourcecode.swift');test_children.append(reference);test_sources.append(build(reference))
tests_group=group('Tests',test_children)
app_product=put('isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = GhostECC.app; sourceTree = BUILT_PRODUCTS_DIR;')
test_product=put('isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = GhostECCTests.xctest; sourceTree = BUILT_PRODUCTS_DIR;')
products=group('Products',[app_product,test_product],False)
main=put(f'isa = PBXGroup; children = ({app_group}, {tests_group}, {products}); sourceTree = "<group>";')
# CocoaPods' embed script copies LibSignalClient.framework into the app; Xcode's user-script sandbox blocks that.
base='IPHONEOS_DEPLOYMENT_TARGET = 17.0; SDKROOT = iphoneos; SWIFT_VERSION = 5.0; CLANG_ENABLE_MODULES = YES; SWIFT_ENABLE_EXPLICIT_MODULES = NO; ENABLE_USER_SCRIPT_SANDBOXING = NO;'
project_config=config_list(base)
app_settings='CODE_SIGN_STYLE = Automatic; GENERATE_INFOPLIST_FILE = YES; INFOPLIST_KEY_CFBundleDisplayName = "Ghost ECC"; INFOPLIST_KEY_NSFaceIDUsageDescription = "Otključaj Ghost ECC."; INFOPLIST_KEY_NSCameraUsageDescription = "Skeniraj QR kod Ghost pozivnice."; INFOPLIST_KEY_NSMicrophoneUsageDescription = "Snimi glasovnu poruku. Zvuk ostaje samo u memoriji."; INFOPLIST_FILE = GhostECC/Info.plist; INFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES; INFOPLIST_KEY_UIUserInterfaceStyle = Dark; INFOPLIST_KEY_UIApplicationSupportsIndirectInputEvents = YES; PRODUCT_BUNDLE_IDENTIFIER = net.ghostecc.app; CODE_SIGN_ENTITLEMENTS = GhostECC/GhostECC.entitlements; PRODUCT_NAME = "$(TARGET_NAME)"; TARGETED_DEVICE_FAMILY = 1; MARKETING_VERSION = 1.0.0; CURRENT_PROJECT_VERSION = 1; SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon; ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor; SWIFT_ENABLE_EXPLICIT_MODULES = NO;'
app_configs=config_list(app_settings, ' ENABLE_TESTABILITY = YES;')
test_configs=config_list('CODE_SIGN_STYLE = Automatic; GENERATE_INFOPLIST_FILE = YES; PRODUCT_BUNDLE_IDENTIFIER = net.ghostecc.app.tests; PRODUCT_NAME = "$(TARGET_NAME)"; TARGETED_DEVICE_FAMILY = 1; BUNDLE_LOADER = "$(TEST_HOST)"; TEST_HOST = "$(BUILT_PRODUCTS_DIR)/GhostECC.app/GhostECC";')
app_phase=phase('PBXSourcesBuildPhase',app_sources)
app_resources=phase('PBXResourcesBuildPhase',[build(asset_ref),build(privacy_ref),build(localizable_ref),build(infoplist_strings_ref)])
app_frameworks=phase('PBXFrameworksBuildPhase',[])
test_phase=phase('PBXSourcesBuildPhase',test_sources);test_resources=phase('PBXResourcesBuildPhase',[]);test_frameworks=phase('PBXFrameworksBuildPhase',[])
app_target=put('');test_target=put('');project=put('')
proxy=put(f'isa = PBXContainerItemProxy; containerPortal = {project}; proxyType = 1; remoteGlobalIDString = {app_target}; remoteInfo = GhostECC;')
dep=put(f'isa = PBXTargetDependency; target = {app_target}; targetProxy = {proxy};')
update(app_target,f'isa = PBXNativeTarget; buildConfigurationList = {app_configs}; buildPhases = ({app_phase}, {app_frameworks}, {app_resources}); buildRules = (); dependencies = (); name = GhostECC; productName = GhostECC; productReference = {app_product}; productType = "com.apple.product-type.application";')
update(test_target,f'isa = PBXNativeTarget; buildConfigurationList = {test_configs}; buildPhases = ({test_phase}, {test_frameworks}, {test_resources}); buildRules = (); dependencies = ({dep}); name = GhostECCTests; productName = GhostECCTests; productReference = {test_product}; productType = "com.apple.product-type.bundle.unit-test";')
update(project,f'isa = PBXProject; attributes = {{ LastUpgradeCheck = 1600; TargetAttributes = {{ {test_target} = {{ TestTargetID = {app_target}; }}; }}; }}; buildConfigurationList = {project_config}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; knownRegions = (en, Base, "sr-Latn", sr, hr, bs); mainGroup = {main}; productRefGroup = {products}; projectDirPath = ""; projectRoot = ""; targets = ({app_target}, {test_target});')
text='// !$*UTF8*$!\n{ archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n'+'\n'.join(key+' = { '+body+' };' for key,body in objects.items())+'\n}; rootObject = '+project+'; }\n'
text=text.replace('\\"','"')
(ROOT/'GhostECC.xcodeproj/project.pbxproj').write_text(text)
def scheme_ref(identifier,name,product): return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{identifier}" BuildableName="{product}" BlueprintName="{name}" ReferencedContainer="container:GhostECC.xcodeproj"/>'
a=scheme_ref(app_target,'GhostECC','GhostECC.app');t=scheme_ref(test_target,'GhostECCTests','GhostECCTests.xctest')
scheme=f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{a}</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO">{t}</TestableReference></Testables></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">{a}</BuildableProductRunnable></LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO"><BuildableProductRunnable runnableDebuggingMode="0">{a}</BuildableProductRunnable></ProfileAction>
<AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>'''
(ROOT/'GhostECC.xcodeproj/xcshareddata/xcschemes/GhostECC.xcscheme').write_text(scheme)
print('Generated Xcode project:', len(app_sources), 'app sources,',len(test_sources),'test sources, icon, privacy manifest.')
