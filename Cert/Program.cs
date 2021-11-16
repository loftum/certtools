using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Cert
{
    internal class Program
    {
        public static async Task<int> Main(string[] args)
        {
            if (!args.Any())
            {
                PrintUsage();
                return 0;
            }

            try
            {
                switch (args[0])
                {
                    case "ca":
                    {
                        var input = new CaRequest
                        {
                            CommonName = "nrk-innlogging-ca",
                            Organization = "NRK",
                            CountryCode = "NO",
                            NotBefore = DateTimeOffset.UtcNow,
                            NotAfter = DateTimeOffset.UtcNow.AddYears(5),
                        };
                        var ca = CertificateGenerator.CreateCa(input);
                        
                        var bytes = ca.Export(X509ContentType.Pfx);
                        await File.WriteAllBytesAsync("ca.pfx", bytes);
                        break;
                    }
                    case "generate":
                    {
                        var input = new CertRequest
                        {
                            CommonName = "nrk-innlogging-client",
                            Organization = "NRK",
                            CountryCode = "NO",
                            NotBefore = DateTimeOffset.UtcNow,
                            NotAfter = DateTimeOffset.UtcNow.AddYears(5),
                        };
                        var cert = CertificateGenerator.CreateCertificate(input);
                        
                        var bytes = cert.Export(X509ContentType.Pfx);
                        await File.WriteAllBytesAsync("ca.pfx", bytes);
                        break;
                    }
                    default:
                        PrintUsage();
                        break;
                }
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return -1;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("generate");
        }
    }
}



