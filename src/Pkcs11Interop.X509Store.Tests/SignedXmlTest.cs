/*
 *  Copyright 2017-2022 The Pkcs11Interop Project
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

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class SignedXmlTest
    {
        // Modified sample from https://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml(v=vs.110).aspx
        [Test()]
        public void MsdnSignedXmlTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                // Find signing certificate
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                // Get PKCS#11 based private key
                RSA rsaPrivateKey = cert.GetRSAPrivateKey();

                // Get software based public key
                RSA rsaPublicKey = cert.Info.ParsedCertificate.PublicKey.Key as RSA;

                // Determine paths
                string basePath = GetBasePath();
                string plainXmlFilePath = Path.Combine(basePath, "Example.xml");
                string signedXmlFilePath = Path.Combine(basePath, "SignedExample.xml");

                // Create an XML file to sign
                CreateSomeXml(plainXmlFilePath);

                // Sign the XML that was just created and save it in a new file
                SignXmlFile(plainXmlFilePath, signedXmlFilePath, rsaPrivateKey);

                // Verify the signature of the signed XML
                bool result = VerifyXmlFile(signedXmlFilePath, rsaPublicKey);

                // Check the results of the signature verification
                Assert.IsTrue(result);
            }
        }

        // Copied from https://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml(v=vs.110).aspx
        // Sign an XML file and save the signature in a new file. This method does not  
        // save the public key within the XML file.  This file cannot be verified unless  
        // the verifying code has the key with which it was signed.
        public static void SignXmlFile(string FileName, string SignedFileName, RSA Key)
        {
            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Load the passed XML file using its name.
            doc.Load(new XmlTextReader(FileName));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document. 
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false));
            doc.WriteTo(xmltw);
            xmltw.Close();
        }

        // Copied from https://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml(v=vs.110).aspx
        // Verify the signature of an XML file against an asymetric 
        // algorithm and return the result.
        public static Boolean VerifyXmlFile(String Name, RSA Key)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document. 
            xmlDocument.Load(Name);

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result.
            return signedXml.CheckSignature(Key);
        }

        // Copied from https://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml(v=vs.110).aspx
        // Create example data to sign.
        public static void CreateSomeXml(string FileName)
        {
            // Create a new XmlDocument object.
            XmlDocument document = new XmlDocument();

            // Create a new XmlNode object.
            XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");

            // Add some text to the node.
            node.InnerText = "Example text to be signed.";

            // Append the node to the document.
            document.AppendChild(node);

            // Save the XML document to the file name specified.
            XmlTextWriter xmltw = new XmlTextWriter(FileName, new UTF8Encoding(false));
            document.WriteTo(xmltw);
            xmltw.Close();
        }

        /// <summary>
        /// Gets absolute path of directory where the test assembly is located
        /// </summary>
        /// <returns>Absolute path of directory where the test assembly is located</returns>
        public static string GetBasePath()
        {
            string basePath = typeof(SoftHsm2Manager).Assembly.CodeBase;
            basePath = new Uri(basePath).LocalPath;
            return Path.GetDirectoryName(basePath);
        }
    }
}
