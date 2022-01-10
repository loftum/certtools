using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Cert.Core;

namespace Cert
{
    public class CertificateCommands
    {
        public static void CreateCa(string commonName,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            string organization,
            string outPath,
            string countryCode = "NO",
            string[] organizationalUnits = null)
        {
            var input = new CaInput
            {
                Organization = organization,
                CommonName = commonName,
                CountryCode = countryCode,
                NotBefore = notBefore,
                NotAfter = notAfter,
                OrganizationalUnits = organizationalUnits
            };
            
            using var ca = CertificateGenerator.CreateCa(input);
            
            File.WriteAllBytes(outPath, ca.Export(X509ContentType.Pfx));
        }

        public static void Create(CertType type,
            string commonName,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            string organization,
            string caPath,
            string outPath,
            string[] dnsNames,
            string countryCode = "NO",
            string[] organizationalUnits = null)
        {
            var caCert = ReadCertFile(caPath);

            var input = new CertInput
            {
                Type = type,
                Organization = organization,
                CommonName = commonName,
                NotBefore = notBefore,
                NotAfter = notAfter,
                CountryCode = countryCode,
                DnsNames = dnsNames,
                OrganizationalUnits = organizationalUnits,
                Ca = caCert
            };
            
            using var cert = CertificateGenerator.CreateCertificate(input);
            
            File.WriteAllBytes(outPath, cert.Export(X509ContentType.Pfx));
        }

        public static void Export(string inputPath, string outputPath)
        {
            using var cert = ReadCertFile(inputPath);
            var bytes = cert.Export(X509ContentType.Cert);
            File.WriteAllBytes(outputPath, bytes);
        }

        private static X509Certificate2 ReadCertFile(string path)
        {
            var bytes = File.ReadAllBytes(path);
            var cert = new X509Certificate2(bytes);
            return cert;
        }

        public static void Read(string file)
        {
            using var cert = ReadCertFile(file);

            
            var builder = new StringBuilder()
                .AppendLine($"Friendly name: {cert.FriendlyName}")
                .AppendLine($"Thumbprint: {cert.Thumbprint}")
                .AppendLine($"Version: {cert.Version}")
                .AppendLine($"Not before: {cert.NotBefore}")
                .AppendLine($"Not after: {cert.NotAfter}")
                .AppendLine($"Serial number: {cert.SerialNumber}")
                .AppendLine($"Issuer: {cert.IssuerName.Format(true)}")
                .AppendLine($"Subject name: {cert.SubjectName.Format(true)}")
                .AppendLine($"Has private key: {cert.HasPrivateKey}")
                ;

            if (cert.Extensions.Any())
            {
                builder.AppendLine()
                    .AppendLine("Extensions:");
                foreach (var extension in cert.Extensions.Where(e => e.Oid != null))
                {
                    builder.AppendLine($"{extension.Oid?.Value} ({extension.Oid?.FriendlyName})");
                }
            }
            
            Console.WriteLine(builder);
        }
    }
}