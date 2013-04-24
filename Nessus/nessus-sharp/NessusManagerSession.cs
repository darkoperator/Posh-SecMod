using System;
using System.Collections;
using System.Xml;
using System.IO;
using System.Net;
using System.Text;

namespace Nessus.Data
{
	public class NessusManagerSession : IDisposable
	{
		string _host;
		string _port = "8834";
		string _proto = "https";
		
		public NessusManagerSession (string host)
		{
			_host = host;
		}
		
		public NessusManagerSession (string host, int port)
		{
			_host = host;
			_port = port.ToString();
		}
		
		public NessusManagerSession (string protocol, string host, int port)
		{
			_host = host;
			_proto = protocol;
			_port = port.ToString();
		}
		
		public string Token { get; private set; }
		
		public string Username { get; private set; }
		
		public string Password { get; private set; }
		
		public bool IsAuthenticated { get; private set; }
		
		public bool IsAdministrator { get; private set; }
		
		public XmlDocument Authenticate(string username, string password, int seq, out bool loggedIn)
		{
			this.Password = password;
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			options.Add("password", password);
			options.Add("login", username);
			
			XmlDocument response = ExecuteCommand("/login", options);
			
			foreach (XmlNode child in response.LastChild.ChildNodes) //first child is XmlDeclaration, we don't care...
			{
				if (child.Name == "seq")
				{
					if (int.Parse(child.InnerText) != seq)
						throw new Exception("Sequences do not match");
				}
				else if (child.Name == "status")
				{
					if (child.InnerText != "OK")
						throw new Exception("Authentication failed");
					else
						this.IsAuthenticated = true;
				}
				else if (child.Name == "contents")
				{
					foreach (XmlNode contentChild in child.ChildNodes)
					{
						if (contentChild.Name == "token")
							this.Token = contentChild.InnerText;
						
						else if (contentChild.Name == "user")
						{
							foreach (XmlNode userChild in contentChild.ChildNodes)
							{
								if (userChild.Name == "name")
									this.Username = userChild.InnerText;
								else if (userChild.Name == "admin")
									this.IsAdministrator = Boolean.Parse(userChild.InnerText);
							}
						}
					}
				}
				
			}
			
			loggedIn = this.IsAuthenticated;
			
			return response;
			
		}
		
		public XmlDocument ExecuteCommand(string uri,  Hashtable options)
		{
            HttpWebRequest request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;
			XmlDocument response = null;
			
            //This is unsafe. TODO
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, ssl) => true; //anonymous delegates ftw!
			
			request.KeepAlive = true;
			request.ProtocolVersion = HttpVersion.Version10;
            request.Method = "POST";
			request.ContentType = "application/x-www-form-urlencoded";
			
			if (!string.IsNullOrEmpty(this.Token))
				request.Headers.Add("Cookie", "token=" + this.Token);
			
            try
            {
				string postData = string.Empty;
			
				foreach (DictionaryEntry de in options)
					postData = postData + de.Key + "=" + de.Value + "&";
				
				postData = postData.Remove(postData.Length - 1); //remove trailing '&'
				
	            byte[] byteArray = Encoding.ASCII.GetBytes(postData);
	
	            request.ContentLength = byteArray.Length;
				
	            using (Stream dataStream = request.GetRequestStream())
	            	dataStream.Write(byteArray, 0, byteArray.Length);
				
				response = new XmlDocument();
				
	            using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
	                using (Stream responseStream = r.GetResponseStream())
						response.Load(responseStream);
            }
            catch 
            {
				
                bool loggedIn = false;
                this.Authenticate(this.Username, this.Password, 1234, out loggedIn);
				
                string postData = string.Empty;
                request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;
					
                request.KeepAlive = true;
                request.ProtocolVersion = HttpVersion.Version10;
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
				
                foreach (DictionaryEntry de in options)
                    postData = postData + de.Key + "=" + de.Value + "&";
				
                postData = postData.Remove(postData.Length - 1); //remove trailing '&'
				
                byte[] byteArray = Encoding.ASCII.GetBytes(postData);

                request.ContentLength = byteArray.Length;
				
                using (Stream dataStream = request.GetRequestStream())
                    dataStream.Write(byteArray, 0, byteArray.Length);
				
                response = new XmlDocument();
				
                using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
                    using (Stream responseStream = r.GetResponseStream())
                        response.Load(responseStream);
				
                if (loggedIn == false)
                    throw new Exception("Can't relogin");
            }
			
			return response;
		}

        public XmlDocument UpLoad(string uri, string Filename)
        {
            HttpWebRequest request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;
            XmlDocument response = null;

            //This is unsafe. TODO
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, ssl) => true;

            string boundary = "----------------------------" + DateTime.Now.Ticks.ToString("x");
            
            request.KeepAlive = true;
            request.ProtocolVersion = HttpVersion.Version10;
            request.Method = "POST";
            request.ContentType = "multipart/form-data; boundary=" + boundary;

            if (!string.IsNullOrEmpty(this.Token))
                request.Headers.Add("Cookie", "token=" + this.Token);

            // Prepare proper message 
            Stream memStream = new System.IO.MemoryStream();
            byte[] boundarybytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");
            string formdataTemplate = "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"{0}\";\r\n\r\n{1}";
            string formitem = string.Format(formdataTemplate, "Filename", Path.GetFileName(Filename));
            byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
            memStream.Write(formitembytes, 0, formitembytes.Length);
            memStream.Write(boundarybytes, 0, boundarybytes.Length);
            string headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
            string header = string.Format(headerTemplate, "Filedata", Path.GetFileName(Filename));
            byte[] headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
            string footerTemplate = "Content-Disposition: form-data; name=\"Upload\"\r\n\r\nSubmit Query\r\n" + boundary + "--";
            byte[] footerBytes = System.Text.Encoding.UTF8.GetBytes(footerTemplate);
            memStream.Write(headerbytes, 0, headerbytes.Length);

            // Read file for upload
            byte[] filecontent = File.ReadAllBytes(Filename);
            memStream.Write(filecontent, 0, filecontent.Length);
            
            // Add file content to message
            memStream.Write(boundarybytes, 0, boundarybytes.Length);
            memStream.Write(footerBytes, 0, footerBytes.Length);

            request.ContentLength = memStream.Length;
            Stream requestStream = request.GetRequestStream();
            memStream.Position = 0;
            byte[] tempBuffer = new byte[memStream.Length];
            memStream.Read(tempBuffer, 0, tempBuffer.Length);

            memStream.Close();
            requestStream.Write(tempBuffer, 0, tempBuffer.Length);
            requestStream.Close();
            try
            {
                response = new XmlDocument();

                using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
                using (Stream responseStream = r.GetResponseStream())
                    response.Load(responseStream);
            }
            catch
            {

                bool loggedIn = false;
                this.Authenticate(this.Username, this.Password, 1234, out loggedIn);

                string postData = string.Empty;
                request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;
                response = null;

                //This is unsafe. TODO
                ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, ssl) => true;

                boundary = "----------------------------" + DateTime.Now.Ticks.ToString("x");
            
                request.KeepAlive = true;
                request.ProtocolVersion = HttpVersion.Version10;
                request.Method = "POST";
                request.ContentType = "multipart/form-data; boundary=" + boundary;

                if (!string.IsNullOrEmpty(this.Token))
                    request.Headers.Add("Cookie", "token=" + this.Token);

                memStream = new System.IO.MemoryStream();
                boundarybytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");
                formdataTemplate = "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"{0}\";\r\n\r\n{1}";
                formitem = string.Format(formdataTemplate, "Filename", Path.GetFileName(Filename));
                formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
                memStream.Write(formitembytes, 0, formitembytes.Length);
                memStream.Write(boundarybytes, 0, boundarybytes.Length);
                headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\n Content-Type: application/octet-stream\r\n\r\n";
                header = string.Format(headerTemplate, "Filedata", Path.GetFileName(Filename));
                headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
                footerTemplate = "Content-Disposition: form-data; name=\"Upload\"\r\n\r\nSubmit Query\r\n" + boundary + "--";
                footerBytes = System.Text.Encoding.UTF8.GetBytes(footerTemplate);
                memStream.Write(headerbytes, 0, headerbytes.Length);

                filecontent = File.ReadAllBytes(Filename);
                memStream.Write(filecontent, 0, filecontent.Length);

                memStream.Write(boundarybytes, 0, boundarybytes.Length);
                memStream.Write(footerBytes, 0, footerBytes.Length);

                request.ContentLength = memStream.Length;
                requestStream = request.GetRequestStream();
                memStream.Position = 0;
                tempBuffer = new byte[memStream.Length];
                memStream.Read(tempBuffer, 0, tempBuffer.Length);

                memStream.Close();
                requestStream.Write(tempBuffer, 0, tempBuffer.Length);
                requestStream.Close();
                response = new XmlDocument();

                    using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
                    using (Stream responseStream = r.GetResponseStream())
                        response.Load(responseStream);

                if (loggedIn == false)
                    throw new Exception("Can't relogin");
            }

            return response;
        }

        // For use when performing queries with option json=1 so as to get a
        // string representation of a JSON file as used by the HTML5 interface.
        // The option json=1 must be hiven for the calls
        public String ExecuteCommand2(string uri, Hashtable options)
        {
            HttpWebRequest request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;
            String response = null;

            //This is unsafe. TODO
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, ssl) => true; //anonymous delegates ftw!

            request.KeepAlive = true;
            request.ProtocolVersion = HttpVersion.Version10;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";

            if (!string.IsNullOrEmpty(this.Token))
                request.Headers.Add("Cookie", "token=" + this.Token);

            try
            {
                string postData = string.Empty;

                foreach (DictionaryEntry de in options)
                    postData = postData + de.Key + "=" + de.Value + "&";

                postData = postData.Remove(postData.Length - 1); //remove trailing '&'

                byte[] byteArray = Encoding.ASCII.GetBytes(postData);

                request.ContentLength = byteArray.Length;

                using (Stream dataStream = request.GetRequestStream())
                    dataStream.Write(byteArray, 0, byteArray.Length);

            
                using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
                using (Stream responseStream = r.GetResponseStream())

                using (StreamReader readStream = new StreamReader(responseStream))
                response = readStream.ReadToEnd();
            }
           catch
           {

               bool loggedIn = false;
               this.Authenticate(this.Username, this.Password, 1234, out loggedIn);

               string postData = string.Empty;
               request = WebRequest.Create(_proto + "://" + _host + ":" + _port + uri) as HttpWebRequest;

               request.KeepAlive = true;
               request.ProtocolVersion = HttpVersion.Version10;
               request.Method = "POST";
               request.ContentType = "application/x-www-form-urlencoded";

               foreach (DictionaryEntry de in options)
                   postData = postData + de.Key + "=" + de.Value + "&";

               postData = postData.Remove(postData.Length - 1); //remove trailing '&'

               byte[] byteArray = Encoding.ASCII.GetBytes(postData);

               request.ContentLength = byteArray.Length;

               using (Stream dataStream = request.GetRequestStream())
                   dataStream.Write(byteArray, 0, byteArray.Length);


               using (HttpWebResponse r = request.GetResponse() as HttpWebResponse)
               using (Stream responseStream = r.GetResponseStream())

               using (StreamReader readStream = new StreamReader(responseStream))
                   response = readStream.ReadToEnd();

               if (loggedIn == false)
                   throw new Exception("Can't relogin");
           }

            return response;
        }
		public void Dispose()
		{
			
		}
	}
}

