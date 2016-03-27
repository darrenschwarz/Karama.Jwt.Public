using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Jose;

namespace Karama.Jwt.UsingJoseJwt
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
                var diff = DateTime.Now.ToUniversalTime() - origin;
                var span = Math.Floor(diff.TotalSeconds) + 60 * 60 * 24;

                //PAYLOAD:DATA
                var payload = new Dictionary<string, object>()
                {
                    { "exp", span },
                    { "iss", "abc"},
                    { "sub" , "sub"},
                    { "aud", "aud"}
                };

                //Microsoft Enhanced Cryptographic Provider v1.0  - Uncomment to demonstrate "Invalid algorithm specified."
                //var privateKey = new X509Certificate2(@"certs\certificate_pubInvalidAlgorithm.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

                //Microsoft Enhanced RSA and AES Cryptographic Provider - Uncomment to demonstrate correct provider usage
                var privateKey = new X509Certificate2(@"certs\certificate_pubWithCSPSpecified.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PrivateKey as RSACryptoServiceProvider;

                if (privateKey != null)
                {                   
                    //This token can now be sent accross the wire, a recipient will use the public key (certificate) 
                    //to compute the hash of the headers & payload and compare it with the signature provided. 
                    var token = JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
                    Console.WriteLine("Token");
                    Console.WriteLine("-----------------------");
                    Console.WriteLine(token);

                    //Demonstrating token verification using just the public key (certificate)
                    var publicKey = new X509Certificate2(@"certs\certificate_pub.crt", "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PublicKey.Key;
                    var decodedToken = JWT.Decode(token, publicKey);
                    Console.WriteLine("-----------------------");
                    Console.WriteLine("Decoded Token: " + decodedToken);
                    Console.WriteLine("Press enter to exit...");
                    Console.ReadLine();
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine("Error");
                Console.WriteLine("-----------------------");
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
                Console.WriteLine("Press enter to exit...");
                Console.ReadLine();
            }
        }
    }
}
