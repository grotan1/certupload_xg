using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Xml.Linq;
using System.Linq;
using System.Dynamic;
//using System.Collections;

namespace certupload
{

    public class DynamicXml : DynamicObject
    {
        XElement _root;
        private DynamicXml(XElement root)
        {
            _root = root;
        }

        public static DynamicXml Parse(string xmlString)
        {
            return new DynamicXml(RemoveNamespaces(XDocument.Parse(xmlString).Root));
        }

        public static DynamicXml Load(string filename)
        {
            return new DynamicXml(RemoveNamespaces(XDocument.Load(filename).Root));
        }

        private static XElement RemoveNamespaces(XElement xElem)
        {
            var attrs = xElem.Attributes()
                        .Where(a => !a.IsNamespaceDeclaration)
                        .Select(a => new XAttribute(a.Name.LocalName, a.Value))
                        .ToList();

            if (!xElem.HasElements)
            {
                XElement xElement = new XElement(xElem.Name.LocalName, attrs);
                xElement.Value = xElem.Value;
                return xElement;
            }

            var newXElem = new XElement(xElem.Name.LocalName, xElem.Elements().Select(e => RemoveNamespaces(e)));
            newXElem.Add(attrs);
            return newXElem;
        }

        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {
            result = null;

            var att = _root.Attribute(binder.Name);
            if (att != null)
            {
                result = att.Value;
                return true;
            }

            var nodes = _root.Elements(binder.Name);
            if (nodes.Count() > 1)
            {
                result = nodes.Select(n => n.HasElements ? (object)new DynamicXml(n) : n.Value).ToList();
                return true;
            }

            var node = _root.Element(binder.Name);
            if (node != null)
            {
                result = node.HasElements || node.HasAttributes ? (object)new DynamicXml(node) : node.Value;
                return true;
            }

            return true;
        }
    }
    class Program
    {
        static string GetMD5HashFromFile(string fileName)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(fileName))
                {
                    return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

        static async Task<string> upload(string certDomainName, string certBotPath, string firewallIP, string firewallPort, string certName)
        {

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (requestMessage, certificate, chain, policyErrors) => true;

            using (var httpClient = new HttpClient(handler))
            {
                using (var request = new HttpRequestMessage(new HttpMethod("POST"), $"https://{firewallIP}:{firewallPort}/webconsole/APIController?"))
                {
                    var multipartContent = new MultipartFormDataContent();
                    multipartContent.Add(new StringContent(File.ReadAllText($"{certDomainName}.xml")), "reqxml");
                    multipartContent.Add(new ByteArrayContent(File.ReadAllBytes(certBotPath + certDomainName + "/" + certName)), "file", Path.GetFileName(certName));
                    multipartContent.Add(new ByteArrayContent(File.ReadAllBytes(certBotPath + certDomainName + "/privkey.key")), "file", Path.GetFileName("privkey.key"));
                    request.Content = multipartContent;

                    var response = await httpClient.SendAsync(request);

                    //    string returnBody = await response.Content.ReadAsStringAsync ();
                    return await response.Content.ReadAsStringAsync();

                    // return "blah";
                }
            }

        }

        static void Main(string[] args)
        {
            // Domain name of certificate
            string certDomainName = "your domain";

            // File name of certificate
            string certName = "fullchain.pem";

            // Change path according to your installation
            string certBotPath = "/etc/letsencrypt/live/";

            string firewallIP = "your ip";

            string firewallPort = "4444";

            // Check if certificate exists
            if (File.Exists(certBotPath + certDomainName + "/" + certName))
            {
                // Creates hash of fullchain.pem
                string hash = GetMD5HashFromFile(certBotPath + certDomainName + "/" + certName);

                // Check if old hash of fullchain.pem exists
                if (File.Exists(certDomainName + ".hash"))
                {
                    var hashReader = new System.IO.StreamReader(certDomainName + ".hash");
                    string oldHash = hashReader.ReadLine();
                    hashReader.Dispose();
                    //   if (hash == oldHash)
                    //   {
                    //        Console.WriteLine("No new certificate availible");
                    // Exit to command line
                    //        return;
                    //     }
                    //     else
                    {
                        Console.WriteLine("New certificate availible uploading...");
                        // Check if privkey.key exists
                        if (System.IO.File.Exists(certBotPath + certDomainName + "/privkey.key"))
                        {
                            // Delete privkey.key if it exists
                            System.IO.File.Delete(certBotPath + certDomainName + "/privkey.key");
                        }
                        // Makes a copy of privkey.pem to privkey.key since Sophos XG only accept .key extension
                        System.IO.File.Copy(certBotPath + certDomainName + "/privkey.pem", certBotPath + certDomainName + "/privkey.key");
                        Task<string> result = upload(certDomainName, certBotPath, firewallIP, firewallPort, certName);
                        string xml = @result.Result;


                        //  var grg = (string)new XmlSerializer(typeof(string), new XmlRootAttribute("yourRootName")); 
                        dynamic response = DynamicXml.Parse(xml);
                        var loginStatus = response.Login.status;
                        Console.WriteLine("Login status: " + loginStatus);
                        if (loginStatus == "Authentication Failure") { return; }
                        var status = response.Certificate.Status.code;
                        Console.WriteLine("Status: " + status);

                        Console.WriteLine(result.Result);

                    }
                    // Prints old hash for debug purpose
                    Console.WriteLine("Old hash: " + oldHash);
                }

                var hashWriter = new System.IO.StreamWriter(certDomainName + ".hash");
                // Write hash to file
                hashWriter.WriteLine(hash);
                hashWriter.Dispose();
                // Prints hash for debug purpose
                Console.WriteLine("Hash: " + hash);
            }
            else Console.WriteLine($"Certificate for {certName} does not exists");

        }

    }

}