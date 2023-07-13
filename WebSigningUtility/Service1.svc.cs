using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Ess;
using System.Text.Json;
using Org.BouncyCastle.Security;

namespace WebSigningUtility
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select Service1.svc or Service1.svc.cs at the Solution Explorer and start debugging.
    public class Service1 : IService1
    {
        public string DllLibPath = "eps2003csp11.dll";
        public string TokenPin = "";
        public string TokenCertificate = "";
        public string certs = " ";
        public bool flag;
        public List<Cert> certList = new List<Cert>();


        public class Cert 
        {
            public string certOwner;
            public string issuedBy;
            public string nationalId;
            public string expiration;
        }

        public string GetData(int value)
        {
            return string.Format("You entered: {0}", value);
        }

        public string getTokens()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);

            var foundCerts = store.Certificates.Find(X509FindType.FindByIssuerName, TokenCertificate, false);

            if (foundCerts != null)
            {
                for (int i = 0; i < foundCerts.Count; i++)
                {
                    Cert cert = new Cert();
                    cert.certOwner = "";
                    cert.issuedBy = "";
                    cert.nationalId = "";
                    cert.expiration = "";
                    string owner = foundCerts[i].GetName();
                    int ownerStart = owner.IndexOf("CN=")+3;
                    int ownerEnd = owner.Substring(ownerStart).IndexOf(",")+ownerStart;
                    int ownerCount = owner.Length;
                    cert.certOwner= owner.Substring(ownerStart, ownerEnd-ownerStart);
                    string issuer = foundCerts[i].GetIssuerName();
                    int issuerStart = issuer.IndexOf("CN=")+3;
                    //int issuerEnd = issuer.Length-1;
                    cert.issuedBy = issuer.Substring(issuerStart);
                    //cert.nationalId = foundCerts[i].GetSerialNumber();
                    string id = foundCerts[i].GetName();
                    int idStart = id.IndexOf("ID")+5;
                    int idEnd = id.Substring(idStart).IndexOf(",")+idStart;
                    int idCount = id.Length;
                    cert.nationalId = id.Substring(idStart, idEnd-idStart);
                    cert.expiration = foundCerts[i].GetExpirationDateString();
                    
                    this.certList.Add(cert);
                }
            }


            string json = JsonSerializer.Serialize(this.certList);
            return json;
        }

        public string signData(string certSerial, string tosign)
        {
             X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);

            var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, certSerial, false);
            if(foundCerts.Count != 1)
            {
                return "Certificate Not Found";
            }

            X509Certificate2 cert= foundCerts[0];

            var privKy = cert.GetRSAPrivateKey();

            byte[] data = Encoding.UTF8.GetBytes(tosign);
            byte[] signedData = privKy.SignData(data,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signedData);


        }

            
    }

            
}
