This small GoLang thing creates random BTC Keys from 128 Bit seed, which is the same as using a 12 word mnemonic, if I'm correct...

It then compares the created key against a bloomfilter (Which has a low percentage of false-positives) to have quick checks....
When a positive match in the bloomfilter is found it is checked against the full file of addresses to check if it's a false-positive or a real one.
If that's also a match it'll save it in foundkeys.txt

Prerequisites:
- GoLang
- Download an address file to check against, for example from http://addresses.loyce.club/ and save as addresses.txt in the same folder
- Update the const in the file to adjust for CPU cores and

That's my first GoLang try, so please let me know if I have errors in the code or can make things faster somewhere...

On my computer it checks 10 Million Keys in about 20 seconds and uses 9.5GB of RAM...
