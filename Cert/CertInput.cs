using System;

namespace Cert
{
    public readonly struct CertInput
    {
        public string CommonName { get; init; }
        public string[] DnsNames { get; init; }
        public DateTimeOffset NotBefore { get; init; }
        public DateTimeOffset NotAfter { get; init; }
        public string CountryCode { get; init; }
        public string Organization { get; init; }
        public string[] OrganizationalUnits { get; init; }
    }
}