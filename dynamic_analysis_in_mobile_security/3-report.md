# Android Security Challenge: Revealing Hidden Functions

---

## 1. Introduction 
This report documents the process of locating, invoking, and retrieving hidden functions within a custom Android application to extract a secret message (flag). The challenge involved reverse engineering, dynamic analysis, and application security assessment using various tools.

### Tools Used

- Android Studio
- Android Emulator (API Level 24+)
- Frida
- Objection
- GDB
- APKTool
- JADX
- Python (for helper scripts) 
---

## Methodology

### Step 1: Decompilation and Code Inspection

1. Decompile the APK using APKTool:
```
Step 1: Decompilation and Code Inspection
```
2. Analyze the Java code with JADX:
```
Analyze the Java code with JADX:
```
3. Identify obfuscated or hidden methods: Look for suspicious classes, methods, or strings that might indicate encryption or concealed functionality


## Step 2: Dynamic Analysis and Hooking

1. Attach Frida to the running application:
```
Attach Frida to the running application:
```
2. List all available functions:
```
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) { console.log(className); },
        onComplete: function() { console.log("Class enumeration complete."); }
    });
});
```

## Step 3: Identifying and Extracting the Flag

 Monitor application logs with Objection:
```
objection -g task3_d explore
```
- List accessible methods: android hooking list classes

- Identify key functions: android hooking search classes secret
---

## Retrieved Flag
```
Holberton{calling_uncalled_functions_is_now_known!}
```

## Conclusion 
By combining reverse engineering and dynamic analysis, the hidden functions were successfully located, invoked, and exploited to retrieve the secret flag. This challenge highlights the importance of secure coding practices to protect sensitive application components.
