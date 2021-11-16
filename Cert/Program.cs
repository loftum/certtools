using System;
using System.Threading.Tasks;
using Cert.Commands;
using Cert.Core;

namespace Cert
{
    internal class Program
    {
        public static async Task<int> Main(string[] args)
        {
            try
            {
                var commander = new Commander().RegisterStaticMethodsOf<CertificateGenerator>();
                commander.Execute(args);
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return -1;
            }
        }
    }
}



