using System;
using System.Collections;
using System.Xml;

namespace Nessus.Data
{
	public class NessusManager : IDisposable
	{
		NessusManagerSession _session;
		
		int RandomNumber { get { return new Random().Next(9999); } }
		
		/// <summary>
		/// Initializes a new instance of the <see cref="AutoAssess.Data.Nessus.NessusManager"/> class.
		/// </summary>
		/// <param name='sess'>
		/// NessesManagerSession configured to connect to the nessus host.
		/// </param>
		public NessusManager (NessusManagerSession sess)
		{
			_session = sess;
		}
		
		/// <summary>
		/// Login the specified username, password and loggedIn.
		/// </summary>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='loggedIn'>
		/// Logged in.
		/// </param>
		public XmlDocument Login(string username, string password, out bool loggedIn)
		{
			return this.Login(username, password, this.RandomNumber, out loggedIn);
		}
		
		/// <summary>
		/// Login the specified username, password, seq and loggedIn.
		/// </summary>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <param name='loggedIn'>
		/// Logged in.
		/// </param>
		public XmlDocument Login(string username, string password, int seq, out bool loggedIn)
		{
			return _session.Authenticate(username, password, seq, out loggedIn);
		}
		
		/// <summary>
		/// Logout this instance.
		/// </summary>
		public XmlDocument Logout ()
		{	
			return this.Logout(this.RandomNumber);
		}
		
		/// <summary>
		/// Logout the specified seq.
		/// </summary>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		public XmlDocument Logout(int seq)
		{
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/logout", options);
			
			return response;
		}
		
		/// <summary>
		/// Adds the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='isAdmin'>
		/// Is admin.
		/// </param>
		public XmlDocument AddUser(string username, string password, bool isAdmin)
		{
			return this.AddUser(username, password, isAdmin, this.RandomNumber);
		}
		
		/// <summary>
		/// Adds the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='isAdmin'>
		/// Is admin.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument AddUser(string username, string password, bool isAdmin, int seq)
		{
			if (!_session.IsAuthenticated || !_session.IsAdministrator)
				throw new Exception("Not authenticated or not administrator");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			options.Add("password", password);
			options.Add("admin", isAdmin ? "1" : "0");
			options.Add("login", username);
			
			XmlDocument response = _session.ExecuteCommand("/users/add", options);
			
			return response;
		}
		
		/// <summary>
		/// Deletes the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		public XmlDocument DeleteUser(string username)
		{
			return this.DeleteUser(username, this.RandomNumber);
		}
		
		/// <summary>
		/// Deletes the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument DeleteUser(string username, int seq)
		{
			if (!_session.IsAuthenticated || !_session.IsAdministrator)
				throw new Exception("Not authed or not admin");
			
			Hashtable options = new Hashtable();
			options.Add("login", username);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/users/delete", options);
			
			return response;
		}
		
		/// <summary>
		/// Edits the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='isAdmin'>
		/// Is admin.
		/// </param>
		public XmlDocument EditUser(string username, string password, bool isAdmin)
		{
			return this.EditUser(username, password, isAdmin, this.RandomNumber);
		}
		
		/// <summary>
		/// Edits the user.
		/// </summary>
		/// <returns>
		/// The user.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='isAdmin'>
		/// Is admin.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument EditUser(string username, string password, bool isAdmin, int seq)
		{
			if (!_session.IsAuthenticated || !_session.IsAdministrator)
				throw new Exception("Not authed or not admin.");
			
			Hashtable options = new Hashtable();
			options.Add("login", username);
			options.Add("password", password);
			options.Add("admin", isAdmin ? "1" : "0");
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/users/edit", options);
			
			return response;
		}
		
		/// <summary>
		/// Changes the user password.
		/// </summary>
		/// <returns>
		/// The user password.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		public XmlDocument ChangeUserPassword(string username, string password)
		{
			return this.ChangeUserPassword(username, password, this.RandomNumber);
		}
		
		/// <summary>
		/// Changes the user password.
		/// </summary>
		/// <returns>
		/// The user password.
		/// </returns>
		/// <param name='username'>
		/// Username.
		/// </param>
		/// <param name='password'>
		/// Password.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ChangeUserPassword(string username, string password, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("login", username);
			options.Add("password", password);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/users/chpasswd", options);
			
			return response;
		}
		
		/// <summary>
		/// Lists the users.
		/// </summary>
		/// <returns>
		/// The users.
		/// </returns>
		public XmlDocument ListUsers()
		{
			return this.ListUsers(this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the users.
		/// </summary>
		/// <returns>
		/// The users.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListUsers(int seq)
		{
			if (!_session.IsAuthenticated || !_session.IsAdministrator)
				throw new Exception("Not authed or not admin.");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/users/list", options);
			
			return response;
		}

 
		/// <summary>
		/// Lists the plugin families.
		/// </summary>
		/// <returns>
		/// The plugin families.
		/// </returns>
		public XmlDocument ListPluginFamilies()
		{
			return this.ListPluginFamilies(this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the plugin families.
		/// </summary>
		/// <returns>
		/// The plugin families.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListPluginFamilies(int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/plugins/list", options);
			
			return response;
		}
		
		/// <summary>
		/// Lists the plugins by family.
		/// </summary>
		/// <returns>
		/// The plugins by family.
		/// </returns>
		/// <param name='family'>
		/// Family.
		/// </param>
		public XmlDocument ListPluginsByFamily(string family)
		{
			return this.ListPluginsByFamily(family, this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the plugins by family.
		/// </summary>
		/// <returns>
		/// The plugins by family.
		/// </returns>
		/// <param name='family'>
		/// Family.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListPluginsByFamily(string family, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("family", family);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/plugins/list/family", options);
			
			return response;
		}
		
		/// <summary>
		/// Gets the plugin descroption by filename.
		/// </summary>
		/// <returns>
		/// The plugin descroption by filename.
		/// </returns>
		/// <param name='filename'>
		/// Filename.
		/// </param>
		public XmlDocument GetPluginDescriptionByFilename(string filename)
		{
			return this.GetPluginDescriptionByFilename(filename, this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the plugin description by filename.
		/// </summary>
		/// <returns>
		/// The plugin description by filename.
		/// </returns>
		/// <param name='filename'>
		/// Filename.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetPluginDescriptionByFilename(string filename, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("fname", filename);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/plugins/description", options);
			
			return response;
		}
		
		/// <summary>
		/// Lists the policies.
		/// </summary>
		/// <returns>
		/// The policies.
		/// </returns>
		public XmlDocument ListPolicies()
		{
			return this.ListPolicies(this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the policies.
		/// </summary>
		/// <returns>
		/// The policies.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListPolicies(int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/policy/list", options);
			
			return response;
		}
        
        public XmlDocument ListTemplates()
        {
            return this.ListTemplates(this.RandomNumber);
        }

        /// <summary>
        /// Lists the policies.
        /// </summary>
        /// <returns>
        /// The policies.
        /// </returns>
        /// <param name='seq'>
        /// Seq.
        /// </param>
        /// <exception cref='Exception'>
        /// Represents errors that occur during application execution.
        /// </exception>
        public XmlDocument ListTemplates(int seq)
        {
            if (!_session.IsAuthenticated)
                throw new Exception("Not authed.");

            Hashtable options = new Hashtable();
            options.Add("seq", seq);

            XmlDocument response = _session.ExecuteCommand("/scan/template/list", options);

            return response;
        }	
		/// <summary>
		/// Deletes the policy.
		/// </summary>
		/// <returns>
		/// The policy.
		/// </returns>
		/// <param name='policyID'>
		/// Policy I.
		/// </param>
		public XmlDocument DeletePolicy(int policyID)
		{
			return this.DeletePolicy(policyID, this.RandomNumber);
		}
		
		/// <summary>
		/// Deletes the policy.
		/// </summary>
		/// <returns>
		/// The policy.
		/// </returns>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument DeletePolicy(int policyID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("policy_id", policyID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/policy/delete", options);
			
			return response;
		}
		
		/// <summary>
		/// Copies the policy.
		/// </summary>
		/// <returns>
		/// The policy.
		/// </returns>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		public XmlDocument CopyPolicy(int policyID)
		{
			return this.CopyPolicy(policyID, this.RandomNumber);
		}
		
		/// <summary>
		/// Copies the policy.
		/// </summary>
		/// <returns>
		/// The policy.
		/// </returns>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument CopyPolicy(int policyID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("policy_id", policyID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/policy/copy", options);
			
			return response;
		}
		
		/// <summary>
		/// Gets the feed information.
		/// </summary>
		/// <returns>
		/// The feed information.
		/// </returns>
		public XmlDocument GetFeedInformation()
		{
			return this.GetFeedInformation(this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the feed information.
		/// </summary>
		/// <returns>
		/// The feed information.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetFeedInformation(int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/feed/", options);
			
			return response;
		}
		
		/// <summary>
		/// Creates the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='target'>
		/// Target.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='name'>
		/// Name.
		/// </param>
		public XmlDocument CreateScan(string target, int policyID, string name)
		{
			return this.CreateScan(target, policyID, name, this.RandomNumber);
		}
		
		/// <summary>
		/// Creates the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='target'>
		/// Target.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument CreateScan(string target, int policyID, string name, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("target", target);
			options.Add("policy_id", policyID);
			options.Add("scan_name", name);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/new", options);
			
			return response;
		}
		
		/// <summary>
		/// Stops the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		public XmlDocument StopScan(String scanID)
		{
			return this.StopScan(scanID, this.RandomNumber);
		}
		
		/// <summary>
		/// Stops the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument StopScan(String scanID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("scan_uuid", scanID.ToString());
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/stop", options);
			
			return response;
		}
		
		/// <summary>
		/// Pauses the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		public XmlDocument PauseScan(String scanID)
		{
			return this.PauseScan(scanID, this.RandomNumber);
		}
		
		/// <summary>
		/// Pauses the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument PauseScan(String scanID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("scan_uuid", scanID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/pause", options);
			
			return response;
		}
		
		/// <summary>
		/// Resumes the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		public XmlDocument ResumeScan(String scanID)
		{
			return this.ResumeScan(scanID, this.RandomNumber);
		}
		
		/// <summary>
		/// Resumes the scan.
		/// </summary>
		/// <returns>
		/// The scan.
		/// </returns>
		/// <param name='scanID'>
		/// Scan ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ResumeScan(String scanID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("scan_uuid", scanID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/resume", options);
			
			return response;
		}
		
		/// <summary>
		/// Lists the scans.
		/// </summary>
		/// <returns>
		/// The scans.
		/// </returns>
		public XmlDocument ListScans()
		{
			return this.ListScans(this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the scans.
		/// </summary>
		/// <returns>
		/// The scans.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListScans(int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/list", options);
			
			return response;
		}
		
		/// <summary>
		/// Creates the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='target'>
		/// Target.
		/// </param>
		public XmlDocument CreateScanTemplate(string name, int policyID, string target)
		{
			return this.CreateScanTemplate(name, policyID, target, this.RandomNumber);
		}
		
		/// <summary>
		/// Creates the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='target'>
		/// Target.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument CreateScanTemplate(string name, int policyID, string target, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("template_name", name);
			options.Add("policy_id", policyID);
			options.Add("target", target);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/template/new", options);
			
			return response;
		}
		
		/// <summary>
		/// Edits the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='readableName'>
		/// Readable name.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='target'>
		/// Target.
		/// </param>
		public XmlDocument EditScanTemplate(string name, string readableName, int policyID, string target)
		{
			return this.EditScanTemplate(name, readableName, policyID, target, this.RandomNumber);
		}
		
		/// <summary>
		/// Edits the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='readableName'>
		/// Readable name.
		/// </param>
		/// <param name='policyID'>
		/// Policy ID.
		/// </param>
		/// <param name='target'>
		/// Target.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument EditScanTemplate(string name, string readableName, int policyID, string target, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("template", name);
			options.Add("template_name", readableName);
			options.Add("policy_id", policyID);
			options.Add("target", target);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/template/edit", options);
			
			return response;
		}
		
		/// <summary>
		/// Deletes the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		public XmlDocument DeleteScanTemplate(string name)
		{
			return this.DeleteScanTemplate(name, this.RandomNumber);
		}
		
		/// <summary>
		/// Deletes the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument DeleteScanTemplate(string name, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("template", name);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/template/delete", options);
			
			return response;
		}
		
		/// <summary>
		/// Launchs the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		public XmlDocument LaunchScanTemplate(string name)
		{
			return this.LaunchScanTemplate(name, this.RandomNumber);
		}
		
		/// <summary>
		/// Launchs the scan template.
		/// </summary>
		/// <returns>
		/// The scan template.
		/// </returns>
		/// <param name='name'>
		/// Name.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument LaunchScanTemplate(string name, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("template", name);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/scan/template/launch", options);
				
			return response;
		}
		
		/// <summary>
		/// Lists the reports.
		/// </summary>
		/// <returns>
		/// The reports.
		/// </returns>
		public XmlDocument ListReports()
		{
			return this.ListReports(this.RandomNumber);
		}
		
		/// <summary>
		/// Lists the reports.
		/// </summary>
		/// <returns>
		/// The reports.
		/// </returns>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument ListReports(int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report/list", options);
			
			return response;
		}
		
		/// <summary>
		/// Deletes the report.
		/// </summary>
		/// <returns>
		/// The report.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		public XmlDocument DeleteReport(string reportID)
		{
			return this.DeleteReport(reportID, this.RandomNumber);
		}
		
		/// <summary>
		/// Deletes the report.
		/// </summary>
		/// <returns>
		/// The report.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument DeleteReport(string reportID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("report", reportID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report/delete", options);
			
			return response;
		}
		
		/// <summary>
		/// Gets the report hosts.
		/// </summary>
		/// <returns>
		/// The report hosts.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		public XmlDocument GetReportHosts(string reportID)
		{
			return this.GetReportHosts(reportID, this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the report hosts.
		/// </summary>
		/// <returns>
		/// The report hosts.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetReportHosts(string reportID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("report", reportID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report2/hosts", options);
			
			return response;
		}
		
		/// <summary>
		/// Gets the ports for host from report.
		/// </summary>
		/// <returns>
		/// The ports for host from report.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		public XmlDocument GetPortsForHostFromReport(string reportID, string host)
		{
			return this.GetPortsForHostFromReport(reportID, host, this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the ports for host from report.
		/// </summary>
		/// <returns>
		/// The ports for host from report.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetPortsForHostFromReport(string reportID, string host, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("report", reportID);
			options.Add("hostname", host);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report2/ports", options);
			
			return response;
		}

        /// <summary>
        /// Check if Report has an Audit Trail for plugin execution
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        public XmlDocument ReportHasAudit(string reportID)
        {
            return this.ReportHasAudit(reportID, this.RandomNumber);
        }

        /// <summary>
        /// Check if Report has an Audit Trail for plugin execution
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        /// <param name='seq'>
        /// Seq.
        /// </param>
        /// <exception cref='Exception'>
        /// Represents errors that occur during application execution.
        /// </exception>
        public XmlDocument ReportHasAudit(string reportID, int seq)
        {
            if (!_session.IsAuthenticated)
                throw new Exception("Not authed.");

            Hashtable options = new Hashtable();
            options.Add("report", reportID);
            options.Add("seq", seq);

            XmlDocument response = _session.ExecuteCommand("/report/hasAuditTrail", options);

            return response;
        }

        /// <summary>
        /// Checks if the report has a KB with debugging data.
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        public XmlDocument ReportHasKB(string reportID)
        {
            return this.ReportHasKB(reportID, this.RandomNumber);
        }

        /// <summary>
        /// Checks if the report has a KB with debugging data.
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        /// <param name='seq'>
        /// Seq.
        /// </param>
        /// <exception cref='Exception'>
        /// Represents errors that occur during application execution.
        /// </exception>
        public XmlDocument ReportHasKB(string reportID, int seq)
        {
            if (!_session.IsAuthenticated)
                throw new Exception("Not authed.");

            Hashtable options = new Hashtable();
            options.Add("report", reportID);
            options.Add("seq", seq);

            XmlDocument response = _session.ExecuteCommand("/report/hasKB", options);

            return response;
        }

        /// <summary>
        /// Retrives a specific plugin execution audit trail.
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        /// <param name='plugin_id'>
        /// Plugin ID.
        /// </param>
        /// <param name='seq'>
        /// Seq.
        /// </param>
        public XmlDocument GetAuditTrail(string reportID, string host, int plugin_id)
        {
            return this.GetAuditTrail(reportID, host, plugin_id, this.RandomNumber);
        }

        /// <summary>
        /// Retrives a specific plugin execution audit trail.
        /// </summary>
        /// <returns>
        /// The report hosts.
        /// </returns>
        /// <param name='reportID'>
        /// Report ID.
        /// </param>
        /// <param name='plugin_id'>
        /// Plugin ID.
        /// </param>
        /// <param name='seq'>
        /// Seq.
        /// </param>
        /// <exception cref='Exception'>
        /// Represents errors that occur during application execution.
        /// </exception>
        public XmlDocument GetAuditTrail(string reportID, string host, int plugin_id, int seq)
        {
            if (!_session.IsAuthenticated)
                throw new Exception("Not authed.");

            Hashtable options = new Hashtable();
            options.Add("plugin_id", plugin_id);
            options.Add("report", reportID);
            options.Add("hostname", host);
            options.Add("seq", seq);

            XmlDocument response = _session.ExecuteCommand("/report/trail-details", options);

            return response;
        }

		/// <summary>
		/// Gets the report details by port and host.
		/// </summary>
		/// <returns>
		/// The report details by port and host.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		/// <param name='port'>
		/// Port.
		/// </param>
		/// <param name='protocol'>
		/// Protocol.
		/// </param>
		public XmlDocument GetReportDetailsByPortAndHost(string reportID, string host, int port, string protocol)
		{
			return this.GetReportDetailsByPortAndHost(reportID, host, port, protocol, this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the report details by port and host.
		/// </summary>
		/// <returns>
		/// The report details by port and host.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		/// <param name='port'>
		/// Port.
		/// </param>
		/// <param name='protocol'>
		/// Protocol.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetReportDetailsByPortAndHost(string reportID, string host, int port, string protocol, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options = new Hashtable();
			options.Add("report", reportID);
			options.Add("hostname", host);
			options.Add("port", port);
			options.Add("protocol", protocol);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report/details", options);
			
			return response;
		}
		
		/// <summary>
		/// Gets the report tags.
		/// </summary>
		/// <returns>
		/// The report tags.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		public XmlDocument GetReportTags(Guid reportID, string host)
		{
			return this.GetReportTags(reportID, host, this.RandomNumber);
		}
		
		/// <summary>
		/// Gets the report tags.
		/// </summary>
		/// <returns>
		/// The report tags.
		/// </returns>
		/// <param name='reportID'>
		/// Report ID.
		/// </param>
		/// <param name='host'>
		/// Host.
		/// </param>
		/// <param name='seq'>
		/// Seq.
		/// </param>
		/// <exception cref='Exception'>
		/// Represents errors that occur during application execution.
		/// </exception>
		public XmlDocument GetReportTags(Guid reportID, string host, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options =  new Hashtable();
			options.Add("report", reportID.ToString());
			options.Add("hostname", host);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/report/tags", options);
			
			return response;
		}
		
		public XmlDocument GetNessusV2Report(string reportID)
		{
			return this.GetNessusV2Report(reportID, this.RandomNumber);
		}
		
		public XmlDocument GetNessusV2Report(string reportID, int seq)
		{
			if (!_session.IsAuthenticated)
				throw new Exception("Not authed.");
			
			Hashtable options =  new Hashtable();
			options.Add("report", reportID);
			options.Add("seq", seq);
			
			XmlDocument response = _session.ExecuteCommand("/file/report/download", options);
			
			return response;
		}

        public XmlDocument GetNessusReportErros(string reportID)
        {
            return this.GetNessusReportErros(reportID, this.RandomNumber);
        }

        public XmlDocument GetNessusReportErros(string reportID, int seq)
        {
            if (!_session.IsAuthenticated)
                throw new Exception("Not authed.");

            Hashtable options = new Hashtable();
            options.Add("report", reportID);
            options.Add("seq", seq);

            XmlDocument response = _session.ExecuteCommand("/report/errors", options);

            return response;
        }

		public void Dispose()
		{}
	}
}

