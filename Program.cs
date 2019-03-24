using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ZeroMQ;
using ZeroMQ.Monitoring;

namespace keyvault
{
    class Program
    {
        private static IConfigurationRoot config;

        static void Main(string[] args)
        {
            config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .AddCommandLine(args)
                .Build();

            KeyVaultClient keyVaultClient = new KeyVaultClient(GetAccessToken);

            var secret = keyVaultClient.GetSecretAsync(config["KeyVault:Url"], "ConnectionString", "650884c5bcd3425a9b74a27e1f55a603").GetAwaiter().GetResult();

            Console.WriteLine($"The super secret connection string is: {secret.Value}");

            MainAsync(args).GetAwaiter().GetResult();

            Console.ReadKey();

            string endpoint;
            using (var context = new ZContext())
            using (var requester = new ZSocket(context, ZSocketType.REQ))
            {
                // Connect
                requester.Connect(endpoint);
                var mon = ZMonitor.Create(context, endpoint2);
                mon.Start()
                for (int n = 0; n < 10; ++n)
                {
                    string requestText = "Hello";
                    Console.Write("Sending {0}…", requestText);

                    // Send
                    requester.Send(new ZFrame(requestText));

                    // Receive
                    using (ZFrame reply = requester.ReceiveFrame())
                    {
                        Console.WriteLine(" Received: {0} {1}!", requestText, reply.ReadString());
                    }
                }
            }





        }

        private static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var clientId = config["AzureActiveDirectory:ClientId"];
            var clientSecret = config["AzureActiveDirectory:ClientSecret"];
            ClientCredential clientCredential = new ClientCredential(clientId, clientSecret);

            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, clientCredential);

            return result.AccessToken;
        }

        //Option 2


        //static void Main(string[] args)
        //{
        //    Task t = MainAsync(args);
        //    t.Wait();
        //}

        static async Task MainAsync(string[] args)
        {
            var keyClient = new KeyVaultClient(async (authority, resource, scope) =>
            {
                var adCredential = new ClientCredential(config["AzureActiveDirectory:ClientId"], config["AzureActiveDirectory:ClientSecret"]);
                var authenticationContext = new AuthenticationContext(authority, null);
                return (await authenticationContext.AcquireTokenAsync(resource, adCredential)).AccessToken;
            });

            // Get the key details
            var keyIdentifier = "https://rahulkeyvault.vault.azure.net:443/keys/NewKey";
            var key = await keyClient.GetKeyAsync(config["KeyVault:Url"]);
            var publicKey = Convert.ToBase64String(key.Key.N);

            using (var rsa = new RSACryptoServiceProvider())
            {
                var p = new RSAParameters() { Modulus = key.Key.N, Exponent = key.Key.E };
                rsa.ImportParameters(p);
                var byteData = Encoding.Unicode.GetBytes(args[0]);

                // Encrypt and Decrypt
                var encryptedText = rsa.Encrypt(byteData, true);
                var decryptedData = await keyClient.DecryptAsync(keyIdentifier, "RSA-OAEP", encryptedText);
                var decryptedText = Encoding.Unicode.GetString(decryptedData.Result);

                // Sign and Verify
                var hasher = new SHA256CryptoServiceProvider();
                var digest = hasher.ComputeHash(byteData);
                var signature = await keyClient.SignAsync(keyIdentifier, "RS256", digest);
                var isVerified = rsa.VerifyHash(digest, "Sha256", signature.Result);
            }
        }
    }
}
