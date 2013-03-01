using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Nessus.Server
{
    //Index            : 0
    //SessionState     : Nessus.Data.NessusManagerSession
    //SessionManager   : Nessus.Data.NessusManager
    //IdleTimeout      : 
    //ScannerBootTime  : 1/28/2013 5:47:49 PM
    //PluginSet        : 201301281115
    //LoaddedPluginSet : 201301281115
    //ServerUUID       : 0851fed3-65b4-fc0f-2548-09c827f17c0a8aa5c6d8a0983574
    //Token            : af49705b7cf3435c3dfb677dd14ac6dc77f08e6d96462901
    //MSP              : FALSE
    //User             : carlos
    //IsAdmin          : True
    public class Session
    {
        public Int32 Index;
        public Nessus.Data.NessusManagerSession SessionState;
        public Nessus.Data.NessusManager SessionManager;
        public string IdleTimeout;
        public DateTime ScannerBootTime;
        public string PluginSet;
        public string LoaddedPluginSet;
        public string ServerUUID;
        public string Token;
        public bool MSP;
        public string ServerHost;
        public string User
        {
            get { return this.SessionState.Username; }
        }
        public bool IsAdmin
        {
            get { return this.SessionState.IsAdministrator; }
        }
    }

    //Name        : carlos
    //IsAdmin     : True
    //LastLogging : 1/30/2013 10:24:01 AM
    public class User
    {
        public string Name;
        public bool IsAdmin;
        public DateTime LastLogging;
        public Nessus.Server.Session Session;
        public string ServerHost
        {
            get { return this.Session.ServerHost; }
        }
    }

    //Feed             : ProFeed
    //ServerVersion    : 5.0.2
    //WebServerVersion : 4.0.26
    //MSP              : False
    //Expiration       : 9/19/2013 4:00:00 AM
    //ServerHost       : 192.168.10.3
    public class FeedInfo
    {
        public string Feed;
        public string ServerVersion;
        public string WebServerVersion;
        public bool MSP;
        public DateTime Expiration;
        public string ServerHost;
    }

    //ReportID   : d2e6b6e0-1eb1-de50-5216-34c1f8b9db0dae7dbaa3a704c053
    //ReportName : home lab
    //Status     : completed
    //KB         : True
    //AuditTrail : True
    //Date       : 1/28/2013 1:54:13 PM
    //Session    :
    //ServerHost : 192.168.10.3

    public class ReportInfo
    {
        public string ReportID;
        public string ReportName;
        public string Status;
        public bool KB;
        public bool AuditTrail;
        public DateTime Date;
        public Nessus.Server.Session Session;
        public string ServerHost
        {
            get { return this.Session.ServerHost; }
        }
    }

    //Host     : 192.168.10.12
    //PluginID : 53521
    //ExitCode : 0
    //Reason   : fedora_2011-5495.nasl was not launched because the key Host/local_checks_enabled is missing
    public class PluginAuditTrail
    {
        public string Host;
        public string ReportName;
        public string ExitCode;
        public string Reason;
    }

    //TemplateID : template-bec91779-b221-6aa2-97f1-7fc3c4b380f55366f11846d22470
    //PolicyID   : -4
    //PolicyName : Internal Network Scan
    //Name       : testsch
    //Owner      : carlos
    //Targets    : 192.168.1.1
    //             192.168.10.10
    //RunRule    : FREQ=ONETIME
    //TimeZone   : Africa/Abidjan
    public class ScanTemplate
    {
        public string TemplateID;
        public Int32 PolicyID;
        public string PolicyName;
        public string Name;
        public string Owner;
        public string Targets;
        public string RunRule;
        public string TimeZone;
        public Nessus.Server.Session Session;
        public string ServerHost
        {
            get { return this.Session.ServerHost; }
        }
    }
}

namespace PKI
{
    namespace Web
    {
        public class WebSSL
        {
            public X509Certificate2 Certificate;
            public string Issuer;
            public string Subject;
            public string[] SubjectAlternativeNames;
            public bool CertificateIsValid;
            public string[] ErrorInformation;
            public HttpWebResponse Response;
        }
    }
}
