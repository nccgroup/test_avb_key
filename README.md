# On *Almost* Signing Android Builds 

## Introduction

An error sometimes encountered by NCC Group consultants is signing Android builds with known private keys. This leaves the device manufacturers (and in turn their users) vulnerable, even on devices where secure boot is enabled. This blog post has two goals: 

* to raise awareness about this issue 
* to introduce a script intended as a quick check to verify if an Android build was (incorrectly) signed with a known private key. 

When Android-based devices boot up, first the bootloader is verified to be running signed code, then the bootloader verifies the high-level operating system (HLOS). This blog post only covers the latter part. 

## Securing the Bootloader – Brief Overview 

Each chipset vendor can implement the root of trust (RoT) differently, but typically, devices are secured by configuring *[e-fuses](https://en.wikipedia.org/wiki/EFuse)*. Immutable ROM code that is burned on the chipset reads these e-fuses and interprets them as bits of a cryptographic hash. The hash is then used to verify a trusted public key, typically included in the bootloader binary. Once the public key has been validated, it is subsequently used to cryptographically verify that the *[first modifiable code that runs on the device is signed](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/secure-boot-and-image-authentication-version_final.pdf)*. If this process is implemented correctly, any attempt to modify the bootloader will fail. OEMs that manufacture Android-based devices (security cameras, smart plugs or sensors, etc.) typically use the chip vendor’s (i.e. Qualcomm) reference design and sample code as the starting point for their product. 

## Android Verified Boot (AVB) 

*[AVB](https://android.googlesource.com/platform/external/avb/+/master/README.md)* is part of the mechanism used to ensure integrity of the software running on a device. Devices contain a partition called *[vbmeta](https://android.googlesource.com/platform/external/avb/+/refs/heads/master/libavb/avb_vbmeta_image.h)* that contains an image that is cryptographically verified. After the bootloader performs a successful verification, the device trusts the content of the vbmeta image. The image contains information the bootloader subsequently uses to validate software present on partitions such as boot, vendor, or system. 

For convenience, chipset vendors provide reference code that compiles successfully out of the box, to simplify the OEM’s device bring-up process. Initially, these images are signed using *[test private keys](https://android.googlesource.com/platform/external/avb/+/refs/tags/android-9.0.0_r37/test/data/testkey_rsa2048.pem)*, first generated by Google, and present on all vanilla Android builds. Sometimes the chip vendors update these test keys, but the private signing keys are still present in the sample code, therefore must be considered untrusted. 

## The Issue 

NCC Group found that device manufacturers may secure the bootloader correctly by configuring the fuses, however they do not change the default test private key used to sign the HLOS. Therefore, while the bootloader cannot be modified, an attacker could build and sign custom HLOS code, and update partitions that will be successfully verified by the AVB process. 

## The Verification Tool 

NCC Group created a *[tool](https://github.com/nccgroup/test_avb_key)* that checks if vbmeta.img includes the public part of a known private key. For the test keys, the tool accepts a path provided by the user (pointed by BOARD_AVB_KEY_PATH environment variable in the Android build), or it uses a collection of known keys collected from GitHub that are included with the tool. 

    $ python3 test_avb_key.py --help 
    Usage: 
         python test_avb_key.py [VBMETA.IMG] [PATH_PRIVATE_KEY] 
    Parameters: 
         * Parameter 'VBMETA.IMG' points to a user or userdebug file from an Android build. 
           Note: the userdebug image fails this test, it is expected. 
         * Grep Android build for 'BOARD_AVB_KEY_PATH' to obtain path of signing file, 
           and leave only the path, i.e. 'external/avb/test/data/'. 

If the HLOS software has been signed with a default private key, and the issue is flagged. For instance, for the LineageOS build:

    $ python test_avb_key.py ./sample/vbmeta/lineage/vbmeta.img ./sample/aosp/external/avb/test/data/
    Opening vbmeta file: ./sample/vbmeta/lineage/vbmeta.img
    
    Using known private key for verification: ./sample/aosp/external/avb/test/data/sign_key.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_pik.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_prk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_psk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_puk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048_gsi.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048_oneplus.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa4096.pem. Public key found at index: 945
    If the script was executed on a vbmeta.img file from an Android user build, there is a problem.

Otherwise, the tool returns a success message, take for instance the Pixel9 build: 

    $ python test_avb_key.py ./sample/vbmeta/pixel9/vbmeta.img ./sample/aosp/external/avb/test/data/
    Opening vbmeta file: ./sample/vbmeta/pixel9/vbmeta.img

    Using known private key for verification: ./sample/aosp/external/avb/test/data/sign_key.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_pik.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_prk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_psk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_atx_puk.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048_gsi.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa2048_oneplus.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa4096.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa4096_oneplus.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa4096_realtek.pem. Public key not found in vbmeta.img file. That's good.
    Using known private key for verification: ./sample/aosp/external/avb/test/data/testkey_rsa8192.pem. Public key not found in vbmeta.img file. That's good.
    No issues were found with ./sample/vbmeta/pixel9/vbmeta.img

Android developers can use this tool as a quick check, to ensure that builds for release/production are not signed using publicly known private keys. It could also be integrated into the build process to ensure Android user builds are correctly signed, or the build will fail.    
