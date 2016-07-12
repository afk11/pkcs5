## PKCS #5 (v2.0) utilities in PHP

    NB: This library is neither *complete* or *fully tested*. 
    If you come across this warning, it means the code isn't suitable to rely
    on yet. Please bear with me, or submit a pull request to speed things along! 

  PKCS #5 is a specification for password-based encryption. It allows users
  to express the encryption algorithm, and key-derivation-function to be used
  with a password to derive a symmetric key.
  
  The scope of this library is initially limited to the primitives recommended
  for new implementations as described in https://tools.ietf.org/html/rfc2898.
  
### Ciphers

 The library works with AES128, AES192, and AES256 ciphers. 
 
### Key derivation function

 Currently, PBKDF2 is the only supported key derivation function. It allows
 the use of SHA1, SHA224, SHA256, SHA384, and SHA512.

 