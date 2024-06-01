# SDKeyUnsealer
A PS4 payload that runs a tcp server that accepts a sealed key (pfsSKKey) and decrypts it.

The payload is made using the PS4 Payload SDK  
https://github.com/Scene-Collective/ps4-payload-sdk

The logic to decrypt the sealed key is based on  
https://github.com/OpenOrbis-Nim/orbis.nim/blob/main/dist/orbis/savedata_advanced.nim

## Usage
To compile run
```
make
```

Make sure you have the ps4-payload-sdk installed and the environment variable set. 

An already compiled version will be available in the releases page.

The port is defined in source/main.c  
An example client is located in example/client.py