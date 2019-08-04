/*
 *  Copyright 2017-2018 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    public static class CryptoObjects
    {
        #region TestCa

        public static string TestCaCert = @"-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQswCQYDVQQGEwJTSzET
MBEGA1UEBxMKQnJhdGlzbGF2YTEQMA4GA1UEAxMHVEVTVCBDQTAgFw0xNzEyMjcw
MDAwMDBaGA8yMTE3MTIyNjIzNTk1OVowNDELMAkGA1UEBhMCU0sxEzARBgNVBAcT
CkJyYXRpc2xhdmExEDAOBgNVBAMTB1RFU1QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDeg9Y2vmlCa/OLaPu0mQvUelm70SnQrbX/hRi236bd3Wq/
JuG/Ye+xaoMn/LZt46lDcnJ9QBfizU6xlfpjrf5PdQR3XMG1bOJFl44iJJxUhguh
SxyIuTGWE3+SlGqLqRNZqKSamFGXFfZpKkHZH3O9cDP3O/6/jix30qCqL3mFEocT
kuvfKTQS2EG3OkvLp65psgO1iBJ9DlDoD+ayXPWFJJForOmrp08hxjCoYKdL8wi9
vzbZUJQC67cu+nE7X+9rsiTi76MstvLWH4hv5e8VoG71PflOE+WhSMLuxslbsfp2
EfuNEYC0O3Q00kc0TtJEegr+aOH4NTaGkTgnFsbDAgMBAAGjPzA9MA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFFdT/QXbx9iINjNSrDEEg9ByHqQbMAsGA1UdDwQE
AwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjF+1o6+fRQ2fNDIMst7+DfYbb/nhJR+Q
b60PSXQfU1et0xflKbCGqQ68PB7xKNSXpgeuRehBfecpYLGAh0R3qrzPGKKwyN25
D/MlO3tlJ3GTYTv2RHI9JvCWS2V6jvwTdO/m6jXYbfrJ9ncJyYg7fWQ1bQiJAWbo
N6rbDaZYrcnJB0JVodWkxiW+cKMZq5aPaN6ONX1jiPDKlGIo9UygJ5H7C9IITpus
LO8kPI+YVJ0lTN/q8IMjn4khmvweV5WfNt6iZ9LuMbhACFyEqgGVWbcXthsL+Yxr
c4ATWyzwriXLPbamxo0Kf27oexY4F9n9d01u2j2XP8f2WkWHGhbRvg==
-----END CERTIFICATE-----";

        public static List<IObjectAttribute> GetTestCaCertAttributes(ISession session, string label)
        {
            X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestCaCert));

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.GetEncoded())
            };
        }

        #endregion

        #region TestUserRsa

        public static string TestUserRsaCert = @"-----BEGIN CERTIFICATE-----
MIIDhzCCAm+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA0MQswCQYDVQQGEwJTSzET
MBEGA1UEBxMKQnJhdGlzbGF2YTEQMA4GA1UEAxMHVEVTVCBDQTAgFw0xNzEyMjcw
MDAwMDBaGA8yMTE3MTIyNjIzNTk1OVowOjELMAkGA1UEBhMCU0sxEzARBgNVBAcT
CkJyYXRpc2xhdmExFjAUBgNVBAMTDVRFU1QgVVNFUiBSU0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDLCXO3zLWm+D3XPkAl0qNzaQHmQhO2pQ1/KHBg
XUM7eLM1VkKvT5R3cBnnE0XHQRhZDGlIOzQ1VD3uKnsWbVvS56rVao5FwFYYzbbi
gaPkkwvnf/3PnL+CN3/UrxrBqGv8uk8Ag5xqEzDObP5h+txuwLPpQin9J+1YKV2g
eRvGMePARWUinYgPAzeFBirA06zxYzdYZkgW4BjrLyb83UVryHwjs7dbQJbSplrK
MzLh42iXzBFy+3+/K2DiRKBO+YTwJQHLqnGtFbdQoDPSSNxtzmJj3uOFp3Z0vOv6
aXOT7CUVHET3dV3RmuePj/5Sn0Fz7slaj/xnBRuVLDSC18+lAgMBAAGjgZswgZgw
DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUOaTQz5s4mOLrZXPYwRvYa9xljqgwXAYD
VR0jBFUwU4AUV1P9BdvH2Ig2M1KsMQSD0HIepBuhOKQ2MDQxCzAJBgNVBAYTAlNL
MRMwEQYDVQQHEwpCcmF0aXNsYXZhMRAwDgYDVQQDEwdURVNUIENBggEBMAsGA1Ud
DwQEAwIEsDANBgkqhkiG9w0BAQsFAAOCAQEAO4xHKky5ieRVG2ZoDXxkBAClslq7
U5ZG7igEppTx3xF/baZPUx417EiE79rFjHd6NlHZ7/wwCFrmPCZ5teWzcFE7SJE6
R090cHCLHgssT6QMc3PPV/HmrQXCgxY18Osa5VMqiOOWJhR/FcVLZS2adeOIr1ml
cMk1NzU9QJnHimIqQSkcUS9SiOinqjSeNnn1lExvcwU1ZBrznPtamKnCiPe8oa2d
oKUO4RuvJDAemsnGfS4ORbu46vzKFV+9ur13HatmO26X7Fsxk66xgNmmKNKpuSYg
4Nc7ByhEX0wBxokQ0sG4R1WkXwPrD6lN2kUYBxY1wnoEUWpNQvphHdk9HQ==
-----END CERTIFICATE-----";

        public static string TestUserRsaPrivKey = @"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLCXO3zLWm+D3X
PkAl0qNzaQHmQhO2pQ1/KHBgXUM7eLM1VkKvT5R3cBnnE0XHQRhZDGlIOzQ1VD3u
KnsWbVvS56rVao5FwFYYzbbigaPkkwvnf/3PnL+CN3/UrxrBqGv8uk8Ag5xqEzDO
bP5h+txuwLPpQin9J+1YKV2geRvGMePARWUinYgPAzeFBirA06zxYzdYZkgW4Bjr
Lyb83UVryHwjs7dbQJbSplrKMzLh42iXzBFy+3+/K2DiRKBO+YTwJQHLqnGtFbdQ
oDPSSNxtzmJj3uOFp3Z0vOv6aXOT7CUVHET3dV3RmuePj/5Sn0Fz7slaj/xnBRuV
LDSC18+lAgMBAAECggEAIf6yJlsbKxqzV/+vQ+XxwhgZ3lC/9jvKd7jwn+HdqO57
qvmHbsz3Qcw+OgdrDoKirf46/oITKr6xI9hvBYFH95ccbmFJ8vnSMJL5BRHJvDK2
sosmlwVat1XNjHHJHBW0Bvu20JI4tTYDXPy41vTmxZB0TyDp4N43iiRa7cx5TwSs
5MUHYiN31PmiyrxT10ob1atnhP4ZK37OASx0oQS/tjQLkoXyjfFEVpwtF4kBKQwt
LhsUHnm/ApMoReHeuuc9yRNHYTapXZZjx5jCG1q3BTIHscEvX0ylaCAlBcVbzJQm
58gw4BNKn7gPhJ/i4hK6JsNwuABdLVLJ+HWJBXrK4QKBgQD0Cw93BKJptR+e/2jD
3TQ9aEAaSCgsRF96F7OLlseTwKeyYDZemM17okpp5u2O+zOBm4cwm8Ik+LMuo2p0
mrjGDct3c6WsoNmjTmLd5LmyQPE1T7jlj+S4/T4/EtQi6RAeoBHFqeyoj+e68iL8
DeTs1NglikpB9DXEN2Qdm/PLKQKBgQDU/BDO/bIYq+4Bo2GSAwyp75LWIYn/Uo+0
CJgw3Os9XpyDJ2Bkc1GHHcbGpNa2llStPLNRNVciuqkfcMxkSN2Ztk0eRI958VdF
uau3fcoWarXqDoFfZehU4j1w+Mq6PLJGzYeH29fTubGDJzoFX09Phih/2guz1H5P
Me7IX3DsHQKBgQDJOFlvBCY6TLqe6e9jGAAb5dp9ESP2pAWpcON85Dz46fAb1tLd
mtZK65y5x0v3Cc8FPczxWmxw+ZMckGeVb4GM5BDxFCz1ssbgrSA933rxrDR2hZ5p
wgSQN1bcwNSjWFIPPmKI/bwBnG4wqbgI5hfs4u65vVXPHeI7QITPGSiiSQKBgH1n
nY4DGqYkNZOJW53ZZc95XH/wZ4yKVEqw9MtwiKIt3wHqYXtD2zEveybjT/laMql+
ICckvRWZypLUm8RAkxo6mNXFkKVAUR6g4Fa+Hgts8YfK2qoNGus/+uVV2CgoLOA7
jB2WeFIV+Es9AZDAObadS6NcA5/y8hw3Tl10tMyRAoGBAOockQt6ctfekkwqAmci
c5GmoFTcLtrNtizJfSYFsT2KhIZz+ZAIAGBTsLPtPbpNG6d4iBwlGzG3UNA763Ug
gUTWJbrzarovAUzgdbqDBYX2Gms35wBgverKYxnRurWID1GemHm7Z98+f5TPW0Qs
W7ahGG6hOe+ZPHr78ZhqZdxN
-----END PRIVATE KEY-----";

        public static List<IObjectAttribute> GetTestUserRsaCertAttributes(ISession session, string label)
        {
            X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestUserRsaCert));

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.GetEncoded())
            };
        }

        public static List<IObjectAttribute> GetTestUserRsaPrivKeyAttributes(ISession session, string label, bool alwaysAuthenticate)
        {
            using (var stringReader = new StringReader(TestUserRsaPrivKey))
            {
                var pemReader = new PemReader(stringReader);
                var rsaPrivKeyParams = pemReader.ReadObject() as RsaPrivateCrtKeyParameters;

                return new List<IObjectAttribute>()
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPrivKeyParams.Modulus.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPrivKeyParams.PublicExponent.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, rsaPrivKeyParams.Exponent.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, rsaPrivKeyParams.P.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, rsaPrivKeyParams.Q.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, rsaPrivKeyParams.DP.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, rsaPrivKeyParams.DQ.ToByteArrayUnsigned()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, rsaPrivKeyParams.QInv.ToByteArrayUnsigned())
                };
            }
        }

        public static List<IObjectAttribute> GetTestUserRsaPubKeyAttributes(ISession session, string label)
        {
            X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestUserRsaCert));
            var rsaPubKeyParams = x509Certificate.GetPublicKey() as RsaKeyParameters;

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned())
            };
        }

        public static RSA GetTestUserPlatformRsaProvider()
        {
            using (var stringReader = new StringReader(TestUserRsaPrivKey))
            {
                var pemReader = new PemReader(stringReader);
                var rsaPrivKeyParams = pemReader.ReadObject() as RsaPrivateCrtKeyParameters;

                RSAParameters rsaParams = new RSAParameters();
                rsaParams.D = rsaPrivKeyParams.Exponent.ToByteArrayUnsigned();
                rsaParams.DP = rsaPrivKeyParams.DP.ToByteArrayUnsigned();
                rsaParams.DQ = rsaPrivKeyParams.DQ.ToByteArrayUnsigned();
                rsaParams.Exponent = rsaPrivKeyParams.PublicExponent.ToByteArrayUnsigned();
                rsaParams.InverseQ = rsaPrivKeyParams.QInv.ToByteArrayUnsigned();
                rsaParams.Modulus = rsaPrivKeyParams.Modulus.ToByteArrayUnsigned();
                rsaParams.P = rsaPrivKeyParams.P.ToByteArrayUnsigned();
                rsaParams.Q = rsaPrivKeyParams.Q.ToByteArrayUnsigned();

                return RSA.Create(rsaParams);

                /*
                if (Platform.IsWindows)
                {
                    RSACng rsa = new RSACng();
                    rsa.ImportParameters(rsaParams);
                    return rsa;
                }
                else
                {
                    RSAOpenSsl rsa = new RSAOpenSsl();
                    rsa.ImportParameters(rsaParams);
                    return rsa;
                }
                */
            }
        }

        #endregion

        #region TestUserEcdsa

        public static string TestUserEcdsaCert = @"-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIBAzANBgkqhkiG9w0BAQsFADA0MQswCQYDVQQGEwJTSzET
MBEGA1UEBxMKQnJhdGlzbGF2YTEQMA4GA1UEAxMHVEVTVCBDQTAgFw0xNzEyMjcw
MDAwMDBaGA8yMTE3MTIyNjIzNTk1OVowPDELMAkGA1UEBhMCU0sxEzARBgNVBAcT
CkJyYXRpc2xhdmExGDAWBgNVBAMTD1RFU1QgVVNFUiBFQ0RTQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABGB/XdAVSi1FQl2L8TqmLhYcmsxGiBa/tba+cK5qdqmf
ZqwILXzlSdgz+M5o3wZfu8t3x5gZUKZwAdOzaMKDar6jgZswgZgwDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQU34+WCC1O937hbFGjtCiJdGvfQIIwXAYDVR0jBFUwU4AU
V1P9BdvH2Ig2M1KsMQSD0HIepBuhOKQ2MDQxCzAJBgNVBAYTAlNLMRMwEQYDVQQH
EwpCcmF0aXNsYXZhMRAwDgYDVQQDEwdURVNUIENBggEBMAsGA1UdDwQEAwIEsDAN
BgkqhkiG9w0BAQsFAAOCAQEAT9XWZTu5R7NA9uJTWJJ3oXkiTMLoXNef1ah58Kaf
ZMBfF8a1DUoYN/KaksOmIg76eplfdJ9bInwj3Gj4bwjCAy8mAvqEFOtZUQ6oRv5a
eAR4LSCVyLX/6lE2hdqD5lo5nuU4dfzWl9dhHBGVg5swOtuzkguQ7H/SA9l2TmtO
YYYobaETZjSLJ3JjoOynaSX/ZL4SJEHbQA60EmfUUxRVLaRdJvDevxYBBvAa3GNu
kHYwe961bLvTJJf5QBTKCtaEwTSrzT6CXmYDU23AncSexOKApjX/xicjBVNjd8NZ
+EPxPFzqOaCIZ0zvS0eAZJVpRcl0lzFGYPW+Ab3ZZOJ9dw==
-----END CERTIFICATE-----";

        public static string TestUserEcdsaPrivKey = @"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLZdzh/Z7DpAt63Ak
f0P9qq5vGhY/fiVfkG1CFsJlQ8uhRANCAARgf13QFUotRUJdi/E6pi4WHJrMRogW
v7W2vnCuanapn2asCC185UnYM/jOaN8GX7vLd8eYGVCmcAHTs2jCg2q+
-----END PRIVATE KEY-----";

        public static List<IObjectAttribute> GetTestUserEcdsaCertAttributes(ISession session, string label)
        {
            X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestUserEcdsaCert));

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.GetEncoded())
            };
        }

        public static List<IObjectAttribute> GetTestUserEcdsaPrivKeyAttributes(ISession session, string label, bool alwaysAuthenticate)
        {
            using (var stringReader = new StringReader(TestUserEcdsaPrivKey))
            {
                var pemReader = new PemReader(stringReader);
                var ecdsaPrivKeyParams = pemReader.ReadObject() as ECPrivateKeyParameters;

                return new List<IObjectAttribute>()
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ALWAYS_AUTHENTICATE, alwaysAuthenticate),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, ecdsaPrivKeyParams.PublicKeyParamSet.GetDerEncoded()),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, ecdsaPrivKeyParams.D.ToByteArrayUnsigned())
                };
            }
        }

        public static List<IObjectAttribute> GetTestUserEcdsaPubKeyAttributes(ISession session, string label)
        {
            X509Certificate x509Certificate = new X509CertificateParser().ReadCertificate(Encoding.ASCII.GetBytes(TestUserEcdsaCert));
            var ecdsaPubKeyParams = x509Certificate.GetPublicKey() as ECPublicKeyParameters;

            return new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, label),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Encoding.ASCII.GetBytes(label)),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, ecdsaPubKeyParams.PublicKeyParamSet.GetDerEncoded()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_POINT, new X9ECPoint(ecdsaPubKeyParams.Q).GetDerEncoded())
            };
        }

        public static ECDsa GetTestUserPlatformEcdsaProvider()
        {
            using (var stringReader = new StringReader(TestUserEcdsaPrivKey))
            {
                var pemReader = new PemReader(stringReader);
                var ecdsaPrivKeyParams = pemReader.ReadObject() as ECPrivateKeyParameters;

                var Q = ecdsaPrivKeyParams.Parameters.G.Multiply(ecdsaPrivKeyParams.D);
                var ecdsaPubKeyParams = new ECPublicKeyParameters(Q, ecdsaPrivKeyParams.Parameters);

                ECParameters ecParams = new ECParameters()
                {
                    Curve = ECCurve.CreateFromValue(ecdsaPrivKeyParams.PublicKeyParamSet.Id),
                    D = ecdsaPrivKeyParams.D.ToByteArrayUnsigned(),
                    Q = new ECPoint()
                    {
                        X = ecdsaPubKeyParams.Q.XCoord.ToBigInteger().ToByteArrayUnsigned(),
                        Y = ecdsaPubKeyParams.Q.YCoord.ToBigInteger().ToByteArrayUnsigned()
                    }
                };

                return ECDsa.Create(ecParams);

                /*
                if (Platform.IsWindows)
                {
                    ECDsaCng ecdsa = new ECDsaCng();
                    ecdsa.ImportParameters(ecParams);
                    return ecdsa;
                }
                else
                {
                    ECDsaOpenSsl ecdsa = new ECDsaOpenSsl();
                    ecdsa.ImportParameters(ecParams);
                    return ecdsa;
                }
                */
            }
        }

        #endregion
    }
}
