# Karama.Jwt.Public
Working with JWT, and resolving the Invalid algorithm specified error.


TL;DR; Generate your .p12 including in your command the -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider" switch.

Our goal is to generate a signed JWT (Javascript Web Token), which in it's simplest form is a string with a delimiter of ".", 
dividing 3 parts (header.payload.signature). 

Without a fair amount of esoteric knowledge, resolving the "Invalid Algorithm Specified." is difficult. This post and the accompanying code will hopefully provide you with an understanding of why this error occurs, and guidance in reproducing and resolving the error. 

NB. This is just one approach to resolving the "Invalid Algorithm Specified." issue. Other solutions involve making changes to the machine config, 
such that the Microsoft Enhanced RSA and AES Cryptographic Provider is used when the RSACryptoProvider hands of to the underlying CSP.

This solution contains two projects; Karama.Jwt.Sha256Specific is intended to make the inner workings
more accessible, and obvious, and Karama.Jwt.UsingJoseJwt is provided as an example of how to use a 3rd party library to achieve the same result 
(Karama.Jwt.Sha256Specific was cobbled together based on code lifted from https://github.com/dvsekhvalnov/jose-jwt).


# Soluition setup
1) Ddownload and installcygwin64, with openssl.

2) Run the following commands in cygwin

###### Create initial certificate
- openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private.key -out certificate_pub.crt

###### Microsoft Enhanced Cryptographic Provider v1.0  - to demonstrate "Invalid algorithm specified.
- openssl pkcs12 -export -in certificate_pub.crt -inkey private.key -out certificate_pubInvalidAlgorithm.p12

###### Microsoft Enhanced RSA and AES Cryptographic Provider - to demonstrate correct provider usage
- openssl pkcs12 -export -in certificate_pub.crt -inkey private.key -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider" -out certificate_pubWithCSPSpecified.p12

3) Copy certificate_pub.crt, certificate_pubInvalidAlgorithm.p12, certificate_pubWithCSPSpecified.p12 and private.key into the certs folder in each project, for each file ensure that "Copy always" is selected against "Copy to Output Directory".

4) Update the password for the private key in Program.cs.

5) Run the projects uncommenting the line with "var privateKey = ..." according the outcome you want to observer (with error, and without) 

If you break point on "if (privateKey != null)", and just above hover over "var privateKey", expand private, expand CspKeyContainerInfo, and look at "ProviderName" you will see that  when using certificate_pubInvalidAlgorithm.p12 the value is "Microsoft Enhanced Cryptographic Provider v1.0", and when using certificate_pubWithCSPSpecified.p12 the value is "Microsoft Enhanced RSA and AES Cryptographic Provider". (see images folder)
https://github.com/darrenschwarz/Karama.Jwt.Public/blob/master/images/MicrosoftEnhancedCryptographicProviderv1.0.jpg
Microsoft Enhanced Cryptographic Provider v1.0 does not support RS256 where as Microsoft Enhanced RSA and AES Cryptographic Provider does.

Hopefully this post is useful and will fast track you to a solution, and a better understanding of the problem space.

Links & ackowledgements
---------------------------------------

https://github.com/dvsekhvalnov/jose-jwt (a great package for workin with JWTs)

http://www.cusoon.fr/update-microsoft-certificate-authorities-to-use-the-sha-2-hashing-algorithm-2/ (backgroound information relating to SHA-2 hashing algorithm)

https://technet.microsoft.com/en-us/library/security/2949927.aspx (Microsoft Security Advisory 2949927)

https://technet.microsoft.com/en-us/library/security/3033929 (Microsoft Security Advisory 3033929)
