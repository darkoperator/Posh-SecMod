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

		public void Dispose()
		{
			
		}
	}
}

