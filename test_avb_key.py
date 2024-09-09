# Description: Checks if a build was signed with a known test private key. This script should
#              normally take as input a user build vbmeta.img file. The vbmeta.img files generated
#              during userdebug builds should normally fail, and that is ok.
# Usage:
# a) using user-provided vbmeta.img and private keys from a build
#       python test_avb_key.py path_to/vbmeta.img path_to_pem_private_keys/
# b) Using user-provided vbmeta.img and sample test private keys.
#       python test_avb_key.py path_to/vbmeta.img
# c) Using the sample vbmeta.img and sample private keys.
#       python test_avb_key.py path_to/vbmeta.img path_to_pem_private_keys/

import os
import sys
import glob

# Debug flag adds extra output data
DEBUG = False 

# Path the private key used in signing, if test key is used. Normally these keya are
# external/avb/test/data/testkey_rsa2048.pem, testkey_rsa4096.pem, or testkey_rsa8192.pem
# when signing a userdebug build. These should not be used on user images.
# Search for the folder pointed by BOARD_AVB_KEY_PATH build variable which is declared in
# either BoardConfig-common.mk or BoardConfig.mk

VBMETA_IMG  = "./sample/vbmeta/lineage/vbmeta.img"
PRIVATE_KEY_PATH = "./sample/aosp/external/avb/test/data/"



#
# Description: reads the content of vbmeta images
# @in     - vbmeta_file_name - filename to read
# @return - byte array containing the public modulus
#
def open_vbmeta_img(vbmeta_file_name):

    print("Opening vbmeta file: " + vbmeta_file_name + "\n")
    fh = open(vbmeta_file_name, "rb")
    result = fh.read()
    fh.close()

    return result



#
# Description: retrieves the public key modulus bytes from give private key (pem format)
# @in     - pem_private_key_file_name - filename to read
# @return - byte array containing the public modulus
#
def bytes_pubkey_from_pem_file(pem_private_key_file_name):

    # check if required tools exist
    output = os.popen("which openssl").read()
    if output == "":
        sys.exit("Error: openssl not installed.")


    # obtain pem file public modulus, unprocessed format
    cmd = "openssl rsa -in " + pem_private_key_file_name + " -pubout 2> /dev/null | openssl rsa -pubin -text -noout 2> /dev/null"
    pubkey_array = os.popen(cmd).readlines()
    if len(pubkey_array) == 0:
        # not a private key
        return None

    if DEBUG:
        print("Command unprocessed output:")
        print("".join(pubkey_array))


    # Check for valid input
    if "Public-Key:" not in pubkey_array[0] or \
        "Modulus:" not in pubkey_array[1] or \
        "Exponent:" not in pubkey_array[len(pubkey_array) - 1]:
        # Must have at least three lines: Public-key, Modulus, and Exponent
        sys.exit("Error reading the private key")


    # combine the public key modulus bytes, ignore first two and the last lines
    str_public_key = ""
    for i in range(2, len(pubkey_array) - 1):
        str_public_key += pubkey_array[i].lstrip().rstrip('\n')

    if DEBUG:
        print("Unprocessed public key bytes:")
        print(str_public_key)


    # create byte array of modulus bytes, reamove the leading byte
    key_bytes = bytearray()
    lst_hex = str_public_key.split(':')
    lst_hex.pop(0)

    for hexval in lst_hex:
        temp_val = bytes.fromhex(hexval)
        key_bytes.extend(temp_val)
   
    return key_bytes



#
# Description: tests if a build is signed with a know private key, i.e.
#              vbmeta image contains public part of known private key.
# @in     - file_name - filename to read
# @return - byte array containing the public modulus
#
def main():

    global VBMETA_IMG
    global PRIVATE_KEY_PATH

    # 
    # 1. Check cmd line params. If specified, overwrite the default values.
    #
    if len(sys.argv) == 3:
        VBMETA_IMG = sys.argv[1]
        PRIVATE_KEY_PATH = sys.argv[2]
    elif len(sys.argv) == 2:
        if sys.argv[1] == "-h" or sys.argv[1] == "--help":
            print("Usage:")
            print("     python test_avb_key.py [VBMETA.IMG] [PATH_PRIVATE_KEY]")
            print("Parameters:")
            print("     * Parameter 'VBMETA.IMG' points to a user or userdebug file from an Android build.")
            print("       Note: the userdebug image normally fails this test, it is expected.")
            print("     * Grep Android build for 'BOARD_AVB_KEY_PATH' to obtain path of signing file,")
            print("       and leave only the path, i.e. 'external/avb/test/data/'.\n")
            sys.exit("Contact GitHub maintainers to report issues with this tool.")
        VBMETA_IMG = sys.argv[1]
    elif len(sys.argv) == 1:
        print("Using sample vbmeta and private key files. Use '--help' option for more details.")
    else:
        sys.exit("Invalid arguments.")


    #
    # 2. Read the vbmeta image file
    #
    vbmeta_bytes = open_vbmeta_img(VBMETA_IMG)


    #
    # 3. Try all private keys in the test key folder, see if they were used
    #    during the signing process.
    #
    all_pem_files = glob.glob(PRIVATE_KEY_PATH + "/*.pem")
    all_pem_files.sort()

    for pem_file in all_pem_files:
        # Extract the public key bytes of the private key pem file
        raw_pub_key = bytes_pubkey_from_pem_file(pem_file)
        if raw_pub_key == None:
            # Not a private key, moving on
            continue
        print("Using known private key for verification:", pem_file, end = '. ')

        # Check if public key bytes are found in the vbmeta image
        found_index = vbmeta_bytes.find(raw_pub_key)
        if found_index < 0:
            print("Public key not found in vbmeta.img file. That's good.")
        else:
            print("Public key found at index:", found_index)
            sys.exit("If the script was executed on a vbmeta.img file from an Android user build, there is a problem.")
    
    print("No issues were found with", VBMETA_IMG)


if __name__ == "__main__":
    main()
