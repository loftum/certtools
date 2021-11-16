using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Cert
{
    public static class CertificateGenerator
    {
        public static X509Certificate2 CreateCa(CaRequest input)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();

            var dn = new StringBuilder();
            
            dn.Append("CN=\"" + input.CommonName.Replace("\"", "\"\"") + "\"");
            
            if (input.OrganizationalUnits != null)
            {
                foreach (var ou in input.OrganizationalUnits)
                {
                    dn.Append(",OU=\"" + ou.Replace("\"", "\"\"") + "\"");
                }    
            }
            
            dn.Append(",O=\"" + input.Organization.Replace("\"", "\"\"") + "\"");
            dn.Append(",C=" + input.CountryCode.ToUpper());

            var distinguishedName = new X500DistinguishedName(dn.ToString());

            using RSA rsa = RSA.Create(4096);
            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            const X509KeyUsageFlags usages = X509KeyUsageFlags.DataEncipherment |
                                             X509KeyUsageFlags.KeyEncipherment |
                                             X509KeyUsageFlags.DigitalSignature |
                                             X509KeyUsageFlags.KeyCertSign;

            request.CertificateExtensions.Add(new X509KeyUsageExtension(usages, false));

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            request.CertificateExtensions.Add(sanBuilder.Build());

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));

            var certificate = request.CreateSelfSigned(input.NotBefore, input.NotAfter);
            return certificate;
        }
        
        public static X509Certificate2 CreateCertificate(CertRequest input)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            if (input.DnsNames == null)
            {
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddDnsName(Environment.MachineName);
            }
            else
            {
                foreach(var dnsName in input.DnsNames)
                {
                    sanBuilder.AddDnsName(dnsName);
                }
            }

            var dn = new StringBuilder();
            
            dn.Append("CN=\"" + input.CommonName.Replace("\"", "\"\"") + "\"");
            
            if (input.OrganizationalUnits != null)
            {
                foreach (var ou in input.OrganizationalUnits)
                {
                    dn.Append(",OU=\"" + ou.Replace("\"", "\"\"") + "\"");
                }    
            }
            
            dn.Append(",O=\"" + input.Organization.Replace("\"", "\"\"") + "\"");
            dn.Append(",C=" + input.CountryCode.ToUpper());

            var distinguishedName = new X500DistinguishedName(dn.ToString());

            using RSA rsa = RSA.Create(4096);
            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            const X509KeyUsageFlags usages = X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature;

            request.CertificateExtensions.Add(new X509KeyUsageExtension(usages, false));


            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            request.CertificateExtensions.Add(sanBuilder.Build());

            request.Create();
            var certificate = request.CreateSelfSigned(input.NotBefore, input.NotAfter);
            return certificate;
        }
    }
}