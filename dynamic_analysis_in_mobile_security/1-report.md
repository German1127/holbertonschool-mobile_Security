# Dynamic Analysis of an Android Application using Frida
## Introduction

This report details the dynamic analysis of the Android application Apk_task1, which utilizes native code through the Java Native Interface (JNI). The objective was to intercept and manipulate native functions using Frida to extract the decrypted flag that is processed within the native code but not displayed in the app interface.
### Tools Used

- Frida: For hooking and modifying native functions.

- ADB (Android Debug Bridge): To interact with the Android device.

- Objection: For simplifying the hooking process.

- Android Studio: For APK analysis and debugging.

Step-by-Step Analysis
### 1. Setting Up the Environment

Installed Frida on both the host machine and the Android device:
```    
    pip install frida-tools
    adb shell "su -c 'setenforce 0'"
    adb push frida-server /data/local/tmp/
    adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
    adb shell "su -c '/data/local/tmp/frida-server &'
```
Verified Frida was working by running:
```    
frida -U -n com.target.app -i
```
### 2. Identifying the Native Library

   
 Extracted the APK and analyzed it using Android Studio and objdump:
```   
 adb shell "run-as com.target.app ls /data/data/com.target.app/lib"
```
    Found libnative-lib.so as the native library.

### 3. Listing JNI Functions

Ran Frida to list available symbols:
```
frida -U -n com.target.app -i -e 'console.log(Module.findExportByName("libnative-lib.so", "getSecretMessage"));'
```
### 4. Hooking the Native Function with Frida
 Wrote a Frida script to intercept getSecretMessage:
```    
	Java.perform(function() {
        var lib = Module.findExportByName("libnative-lib.so", "getSecretMessage");
        Interceptor.attach(lib, {
            onEnter: function(args) {
                console.log("[+] Hooked getSecretMessage");
            },
            onLeave: function(retval) {
                console.log("[+] Flag: " + retval.readUtf8String());
            }
        });
    });
```

 Ran the script:
```    
frida -U -n com.target.app -s hook.js --no-pause
```
 Retrieved the decrypted flag from logs:
```    
adb logcat | grep "Flag:"
```

###Results

The decrypted flag extracted from getSecretMessage is:
```
Holberton{native_hooking_is_no_different_at_all}
```

### Conclusion

By using Frida, we successfully hooked the native function getSecretMessage in the application’s native library and extracted the hidden flag. This demonstrates the effectiveness of dynamic analysis techniques in reverse engineering Android applications that use JNI for sensitive operations.
