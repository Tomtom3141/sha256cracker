# sha256cracker
Proof of concept intended to break sha256 hashes in polynomial time
compile with the following command:
gcc -Wall -std=c99 cracker.c -o cracker

On linux machines intended to be used in the following syntax:
cracker <SHA256 Hash> <min len> <max len>

On windows machines intended to be used in the following syntax:
cracker.exe <SHA256 Hash> <min len> <max len>

There will be no output until the program has found the hash
