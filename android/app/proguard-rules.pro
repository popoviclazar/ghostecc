# libsignal calls back into Java classes from native code by name.
-keep class org.signal.libsignal.** { *; }
# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class net.lazarp.ghostecc.** { *** Companion; }
-keepclasseswithmembers class net.lazarp.ghostecc.** { kotlinx.serialization.KSerializer serializer(...); }
-keep,includedescriptorclasses class net.lazarp.ghostecc.**$$serializer { *; }
# Only BouncyCastle's lightweight Ed25519 classes are used.
-dontwarn org.bouncycastle.**
