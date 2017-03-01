# rsa-buffet

## Challenge
> There are 10 public keys and 5 ciphertexts using them. If you can decode any three you can get a flag.
> [rsa-buffet](rsa-buffer.tar.bz2)

## Solution 

This challenge involves two cryptographic systems: [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) and [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). One must first recover the private key of enough of the RSA public keys to successfully decrypt 3 of the 5 given ciphertexts. There is a [convenient little library on github](https://github.com/xmunoz/RsaCtfTool) that can help you do exactly this, by sequentially executing well know-known attacks on RSA ([Wiener's](https://en.wikipedia.org/wiki/Wiener%27s_attack), [Hastad's](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H.C3.A5stad.27s_broadcast_attack), [Fermat's](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method), [factordb](http://factordb.com/), etc). Using my fork of this library, I ran each of the public keys through the program, and successfully recovered 3 private keys.

```
$ python RsaCtfToolcli.py --publickey ../rsa-buffet/key-1.pem --private
$ python RsaCtfToolcli.py --publickey ../rsa-buffet/key-2.pem --private
$ python RsaCtfToolcli.py --publickey ../rsa-buffet/key-3.pem --private
```

This writes the recovered private keys to a file. Now that we have 3 private keys, we can start trying to decrypt some ciphertexts. I edited the main section of the provided `encrypt.py` file to perform the decryption.

```
if __name__ == "__main__":
    k_text = open(sys.argv[1], 'r').read()
    c = open(sys.argv[2], 'rb').read()
    k = RSA.importKey(k_text)
    print(decrypt(k, c))
```

After some trial-and-error, I found the following key-ciphertext decryption pairs: key1 + ciphertext5, key2 + ciphertext1, key3 + ciphertext4.

```
$ python encrypt.py key1 ciphertext-5.bin
Congratulations, you decrypted a ciphertext!  One down, two to go :)
5-7d29041c468b680fcff93c16011a2869f17de75b929b787503b412becde0321ec72fe1e499f2150a1dacb9a5f701c0b37470049dd560cef5163543469817971f50782f763f0b05ab7088f7ae
5-a7a1e271cf263279cece532b540545fa539b0f3650e2929163b02ee5459debdc53c1e07149eb2153015bb5c88e6270e8
5-149480c5c75cbe320564adfa432ac8ea241e048ed39c8bc6be14ca80c392487f43a7882075d785d62cb314ea6c89a6b5f28adfa56ec481e124567b88241de2a6cabcc7ec9de3acac8be5375b
5-7285289084282d559573f68eef10191091d76d6670014202670651f867cd2bc8640a86eef1c1e482affc7ae801fa446956c2186972fb6b7bac88c91d050c9d3cca
$ python encrypt.py key2 ciphertext-1.bin
Congratulations, you decrypted a ciphertext!  One down, two to go :)
1-32a1cd9f414f14cff6685879444acbe41e5dba6574a072cace6e8d0eb338ad64910897369b7589e6a408c861c8e708f60fbbbe91953d4a73bcf1df11e1ecaa2885bed1e5a772bfed42d776a9
1-e0c113fa1ebea9318dd413bf28308707fd660a5d1417fbc7da72416c8baaa5bf628f11c660dcee518134353e6ff8d37c
1-1b8b6c4e3145a96b1b0031f63521c8df58713c4d6d737039b0f1c0750e16e1579340cfc5dadef4e96d6b95ecf89f52b8136ae657c9c32e96bf4384e18bd8190546ff5102cd006be5e1580053
1-c332b8b93a914532a2dab045ea52b86d4d3950a990b5fc5e041dce9be1fd3912f9978cad009320e18f4383ca71d9d79114c9816b5f950305a6dd19c9f458695d52
$ python encrypt.py key3 ciphertext-4.bin
Congratulations, you decrypted a ciphertext!  One down, two to go :)
4-4a87367d053c533fd995032ed1e651487cb5dc1e0b1cb70a7662b152c73650f039a60f391a52f2413f43bd54eb7b12c41b42f31ac557edd4bfe46a396a8cdbe19dc9d8121924f43be51c976d
4-abbbcee71f140198ff8c50f51069465075979c31d32b052e7ae82ec7f6783aef7b41a597f9504d3340967b8d70cbe5a3
4-35fbbe40058e20463547b363d1f164c0bbbb97cfd9ffe7619bce31a59392f0e9625a2cd035276e09c4df3c0932f22bd322f16e375c7c7fd88da0f972832707eb549ff1e776db37649019ebce
4-12b466934911986bda845d8d26710a12250d210546f46716c78d7a17b1f2c893b95b934c8c7beafcf81a3123eb2ea05ca89101b23349e455794a8d56608c8ee49dd
```

Now with enough secrets from the secret-share, I was able to recover the flag.

```
from secretsharing import PlaintextToHexSecretSharer as SS

files = ["ciphertext5.txt", "ciphertext1.txt", "ciphertext4.txt"]
secrets = []
for fn in files:
    a = []
    with open(fn, "r") as f:
        a = f.readlines()

    a = a[1:] # strip the "Congratulation" line
    for i in range(0,len(a)):
        a[i] = a[i].strip("\n")

    secrets.append(a)

for i in range(0, 2):
    a = SS.recover_secret([secrets[0][i], secrets[1][i], secrets[2][i]])
    print(a)
```

Running this little script produces some out, and the flag.

```
And another one's down, and another one's down, and another one bites the dust!

Three's the magic number!  FLAG{ndQzjRpnSP60NgWET6jX}.
```
