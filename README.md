# GF3208 (5201) Goodix fingerprint reader research

## Goals
* Reverse engineer and document protocol used to control the device
* Write open source linux driver



## Device
* model: GF3208 : 88x108 pixels @500dpi
* found in ASUS UX391F Notebooks
* uses proprietary windows driver 
* its a USB device (internal)
* `lsusb` identifies device as `5201`
* driver location `C:\Program Files\Goodix\Fingerprint Driver` main parts contained in `milanFusb.dll`
* Windows loads the dll in WUDF process
* logs can be enabled with registry `HKEY_LOCAL_MACHINE\SOFTWARE\Goodix\FP\LogOutput` key `LogLevel` (DWORD) set to 9 (max)
* Logs are stored in `C:\ProgramData\Goodix`

## Tools
* Windows 11 `virtual box` VM with USB passthrough 
* USB communication sniffing with `wireshark`
*  disassembly of windows driver using `Ghidra`
* `windbg preview` debugging with time travel

# Protocol
## Image data
* First 5 bytes of of data is image header (purpose not known)
* Last 4 bytes (32bit int) is image crc checksum
* `MPEG2 CRC32` algo is used to calculate image checksum
* Rest of data is encrypted

### Data encryption
* Image data is encrypted with some kind of rolling key encryption
* Every data packet is encrypted with same set of keys 
* Every key is generated form a seed
* Starting seed for key gen is always `0x12345678`
* Next seed is generated from one before  
* Data is decrypted by applying XOR operation with key and every 16bit word

#### Key gen algo:
```python
def rolling_key_gen(seed):
    var1 = seed >> 1 ^ seed
    var2 = seed >> 0x10
    var3 = ((((((((seed >> 0xf & 0x2000 | seed & 0x1000000) >> 1 | seed & 0x20000) >> 2 | seed & 0x1000) >> 3 | (seed >> 7 ^ seed) & 0x80000) >> 1 | (seed >> 0xf ^ seed) & 0x4000) >> 2 | seed & 0x2000) >> 1 | (seed >> 0xe ^ seed) & 0x200) >> 1 | var1 & 0x40 | seed & 0x20) >> 1
    var4 = var3 | ((seed >> 0x14) ^ seed * 2) & 4 | seed & 1
    nextSeed = (var1 >> 0x1e ^ seed >> 10 & 0xff ^ seed & 0xff) << 0x1f | seed >> 1
    key = ((var3 >> 8) | (var2 >> 8 ^ ((seed << 3) >> 8)) & 0x40 | (var2 >> 1 ^ seed) & 8 | (((seed << 6) >> 8) ^ ((seed >> 7) >> 8)) & 1 | (((seed & 0x100) << 7) >> 8)) + var4 * 0x100
    return (key, nextSeed & 0xffffffff)
```

### Image packing
Images are packed in a way where 6 bytes represents 4 16bit words of pixel data

#### Unpacking algo:
```python
def unpack_data_to_16bit(data):
    # 6 bytes are needed to represent 4 16-bit values
    assert (len(data) % 6) == 0
    out = []
    for i in range(0, len(data), 6):
        chunk = data[i:i+6]
        o1 = ((chunk[0] & 0xf) << 8) + chunk[1] 
        o2 = (chunk[3] << 4) + (chunk[0] >> 4)
        o3 = ((chunk[5] & 0xf) << 8) + chunk[2] 
        o4 = (chunk[4] << 4) + (chunk[5] >> 4)
        out += [o1, o2, o3, o4]
    return out
```

# Credits
Code and info from these related and helpful projects were used in this research:
* [https://github.com/mpi3d/goodix-fp-dump](https://github.com/mpi3d/goodix-fp-dump)
* [https://blog.th0m.as/misc/fingerprint-reversing](https://blog.th0m.as/misc/fingerprint-reversing)
* [https://github.com/tlambertz/goodix-fingerprint-reversing](https://github.com/tlambertz/goodix-fingerprint-reversing)
* [https://discord.gg/6xZ6k34Vqg](https://discord.gg/6xZ6k34Vqg)