**DISCLAIMER: THIS IS A BACKUP OF THE CURRENT (_2023-12_) [CRYPTOPALS CRYPTO CHALLENGES SITE](https://cryptopals.com).**
**IT IS BROUGHT HERE FOR THE BACKUP & CONVINIENCE PURPOSE.**
**ALL THE CONTENT & AUTHORSHIP WITH INFORMATION ABOUT CHALLENGES & TASKS BELONGS TO THE ORIGINAL AUTHORS.**

[Set 1 source](https://cryptopals.com/sets/1)

# Crypto Challenge Set 1

This is the **qualifying set**. We picked the exercises in it to ramp
developers up gradually into coding cryptography, but also to verify that
we were working with people who were ready to write code.

This set is **relatively easy**. With one exception, most of these exercises
should take only a couple minutes. But don't beat yourself up if it takes
longer than that. It took Alex two weeks to get through the set!

If you've written any crypto code in the past, you're going to feel like
skipping a lot of this. **Don't skip them**. At least two of them (we won't say
which) are important stepping stones to later attacks.

 1. [Convert hex to base64](#convert-hex-to-base64)
 2. [Fixed XOR](#fixed-xor)
 3. [Single-byte XOR cipher](#single-byte-xor-cipher)
 4. [Detect single-character XOR](#detect-single-character-xor)
 5. [Implement repeating-key XOR](#implement-repeating-key-xor)
 6. [Break repeating-key XOR](#break-repeating-key-xor)
 7. [AES in ECB mode](#aes-in-ecb-mode)
 8. [Detect AES in ECB mode](#detect-aes-in-ecb-mode)


## Convert hex to base64

The string:
```
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```

Should produce:
```
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

**Cryptopals Rule**  
**_`Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.`_**


## Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:
```
1c0111001f010100061a024b53535009181c
```

... after hex decoding, and when XOR'd against:
```
686974207468652062756c6c277320657965
```

... should produce:
```
746865206b696420646f6e277420706c6179
```


## Single-byte XOR cipher

The hex encoded string:
```
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext.
Character frequency is a good metric.
Evaluate each output and choose the one with the best score.

**Achievement Unlocked**
**_`You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.`_**


## Detect single-character XOR

One of the 60-character strings [in this file](challenge-data/4.txt) has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)


## Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:
```
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
```

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E,
then I again for the 4th byte, and so on.

It should come out to:
```
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

Encrypt a bunch of stuff using your repeating-key XOR function.
Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it.
I promise, we aren't wasting your time with this. 


## Break repeating-key XOR

TBA


## AES in ECB mode

TBA


## Detect AES in ECB mode

TBA


