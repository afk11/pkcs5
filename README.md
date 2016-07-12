## PKCS #5 (v2.0) utilities in PHP

> NB: This library is neither *complete* or *fully tested*. If you
  come across this warning, please bear with me, or submit a pull request!

  PKCS #5 is a specification for password-based encryption. It works by
  deriving a symmetric key from a key-derivation-function.  
  
  The scope of this library is initially limited to the primitives recommended
  for new implementations as described in https://tools.ietf.org/html/rfc2898.
  In it's lifetime, PKCS#5 has allowed RC4 and DES, but I don't think I'll
  include support for these yet, just AES.
  
  It allows pbkdf1 and pbkdf2, but again, I'll only support pbkdf2 for now.
  
### Ciphers

 The library works with AES128, AES192, and AES256 ciphers. 
 
### Key derivation function
 Currently, PBKDF2 is the only supported key derivation function. 

 