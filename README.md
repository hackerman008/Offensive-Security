# Offensive-Security

## Project0 - Retrieving Native API addresses and Syscall Ids at runtime
The project demonstrates how windows structures like PEB and the PE file structure can be used to retrieve the api address dynamically at runtime avoiding the use of api's like GetProcAddress and LoadLibrary which are hooked or monitored in the kernel for malicious activity. This can be used by offensive security professionals to make EDR bypassing payloads for red team operations.
