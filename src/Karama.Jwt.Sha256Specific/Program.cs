using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace Karama.Jwt.Sha256Specific
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0);
                var diff = DateTime.Now.ToUniversalTime() - origin;
                var span = Math.Floor(diff.TotalSeconds) + 60*60*24;

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


                var javaScriptSerializer = new JavaScriptSerializer();
                var rs256Managed = new SHA256Managed();
                //HEADER:ALGORITHM & TOKEN TYPE
                var extraHeaders = new Dictionary<string, object> { {"typ","JWT"} };
                var jwtHeader = new Dictionary<string, object> { { "alg", "RS256" } };
                DictionariesAppend(jwtHeader, extraHeaders);
                //Get byte arrays from jwtHeader & payload
                var headerBytes = Encoding.UTF8.GetBytes(javaScriptSerializer.Serialize(jwtHeader));
                var payloadBytes = Encoding.UTF8.GetBytes(javaScriptSerializer.Serialize(payload));
                //Serialize headerBytes & payloadBytes Base64UrlEncoded and delimited by a "."
                var headerBytesPayloadBytesSerialized = Serialize(headerBytes, payloadBytes);
                //Get byte array from headerBytesPayloadBytesSerialized.
                var bytesToSign = Encoding.UTF8.GetBytes(headerBytesPayloadBytesSerialized);

                if (privateKey != null)
                {
                    var pkcs1 = new RSAPKCS1SignatureFormatter(privateKey);
                    pkcs1.SetHashAlgorithm("SHA256");
                    //Here is where you will ecnounter the error "Invalid algorithm specified." if your p12 has been generated without specifying the -CSP  "Microsoft Enhanced RSA and AES Cryptographic Provider" switch
                    var signature = pkcs1.CreateSignature(rs256Managed.ComputeHash(bytesToSign));

                    //This token can now be sent accross the wire, a recipient will use the public key (certificate) 
                    //to compute the hash of the headers & payload and compare it with the signature provided. 
                    var token = Serialize(headerBytes, payloadBytes, signature);
                    Console.WriteLine("Token");
                    Console.WriteLine("-----------------------");
                    Console.WriteLine(token);
                    
                    //Demonstrating token verification using just the public key (certificate)
                    var publicKey = new X509Certificate2(@"certs\certificate_pub.crt", "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet).PublicKey.Key;
                    var verified = Verify(token, publicKey);
                    Console.WriteLine("-----------------------");
                    Console.WriteLine("Verified: " + verified);
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

        #region protected

        public static byte[][] Parse(string token)
        {
            string[] parts = token.Split('.');

            var result = new byte[parts.Length][];

            for (int i = 0; i < parts.Length; i++)
            {
                result[i] = Base64UrlDecode(parts[i]);
            }

            return result;
        }
        
        protected static bool Verify(string token, object key)
        {
            byte[][] parts = Parse(token);

            string json;
            var javaScriptSerializer = new JavaScriptSerializer();

            //signed or plain JWT
            byte[] header = parts[0];
            byte[] payload = parts[1];
            byte[] signature = parts[2];

            byte[] securedInput = Encoding.UTF8.GetBytes(Serialize(header, payload));

            var headerData = javaScriptSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(header));
            var algorithm = (string)headerData["alg"];

            var rs256Managed = new SHA256Managed();
            var publicKey = (AsymmetricAlgorithm)key;

            byte[] hash = rs256Managed.ComputeHash(securedInput);

            var pkcs1 = new RSAPKCS1SignatureDeformatter(publicKey);
            pkcs1.SetHashAlgorithm("SHA256");

            return pkcs1.VerifySignature(hash, signature);
        }

        protected static string Serialize(params byte[][] parts)
        {
            var builder = new StringBuilder();

            foreach (var part in parts)
            {
                builder.Append(Base64UrlEncode(part)).Append(".");
            }

            builder.Remove(builder.Length - 1, 1);

            return builder.ToString();
        }

        protected static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        protected static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }
        protected static void DictionariesAppend<K, V>(IDictionary<K, V> src, IDictionary<K, V> other)
        {
            if (src != null && other != null)
            {
                foreach (var pair in other.Where(pair => !src.ContainsKey(pair.Key)))
                {
                    src.Add(pair);
                }
            }
        }

        #endregion
    }
}
