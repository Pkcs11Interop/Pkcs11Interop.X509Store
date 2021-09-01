using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Net.Pkcs11Interop.X509Store
{
    public static class Pkcs11X509CryptoObjectHelper
    {
        public static List<IObjectAttribute> GetRsaCertAttributes(X509Certificate2 x509Certificate, ISession session, string label)
        {
            //X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestUserRsaCert));

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectName.RawData),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerName.RawData),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, x509Certificate.GetSerialNumber()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.Export(X509ContentType.Cert))
            };
        }

        public static List<IObjectAttribute> GetRsaPrivKeyAttributes(X509Certificate2 x509Certificate, ISession session, string label, bool alwaysAuthenticate)
        {
            var rsaPrivKeyParams = x509Certificate.GetRSAPrivateKey().ExportParameters(true);

            return new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, false),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPrivKeyParams.Modulus),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPrivKeyParams.Exponent),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, rsaPrivKeyParams.D),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, rsaPrivKeyParams.P),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, rsaPrivKeyParams.Q),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, rsaPrivKeyParams.DP),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, rsaPrivKeyParams.DQ),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, rsaPrivKeyParams.InverseQ)
                    };
        }

        //public static List<IObjectAttribute> GetTestUserRsaPrivKeyAttributes(Org.BouncyCastle.X509. x509Certificate,  ISession session, string label, bool alwaysAuthenticate)
        //{
        //    new  RsaPrivateCrtKeyParameters

        //    using (var stringReader = new StringReader(TestUserRsaPrivKey))
        //    {
        //        var pemReader = new PemReader(stringReader);

        //        x509Certificate.G
        //BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger qInv


        //var rsaPrivKeyParams = Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(rsa).Private as RsaPrivateCrtKeyParameters;
        //    //new RsaPrivateCrtKeyParameters(
        //    //new BigInteger(x509CertificatePrivKeyParams.Modulus),
        //    //new BigInteger(x509CertificatePrivKeyParams.Exponent),
        //    //new BigInteger(x509CertificatePrivKeyParams.D),
        //    //new BigInteger(x509CertificatePrivKeyParams.P),
        //    //new BigInteger(x509CertificatePrivKeyParams.Q),
        //    //new BigInteger(x509CertificatePrivKeyParams.DP),
        //    //new BigInteger(x509CertificatePrivKeyParams.DQ),
        //    //new BigInteger(x509CertificatePrivKeyParams.InverseQ)
        //    //);

        //return new List<IObjectAttribute>()
        //    {
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPrivKeyParams.Modulus.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPrivKeyParams.PublicExponent.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, rsaPrivKeyParams.Exponent.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, rsaPrivKeyParams.P.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, rsaPrivKeyParams.Q.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, rsaPrivKeyParams.DP.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, rsaPrivKeyParams.DQ.ToByteArrayUnsigned()),
        //        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, rsaPrivKeyParams.QInv.ToByteArrayUnsigned())
        //    };
    //}

        public static List<IObjectAttribute> GetRsaPubKeyAttributes(X509Certificate2 x509Certificate,  ISession session, string label)
        {
            var rsaPubKeyParams = x509Certificate.GetRSAPublicKey().ExportParameters(false);

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent)
            };
        }
    }
}
