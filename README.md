# ioncube-helper

## DecryptIonCubeXORStrings.py

Ghidra script to help bulk decrypt strings that are stored in an encrypted form in the ionCube loader. 

I've not shipped the key itself with this, it's not quite point-and-click, sorry!

To use: 
1. Find the function responsible for the decryption and name it "global_xor_string".
2. Within this function find the key, and add into the script as a Python bytearray().
3. Run the script.
