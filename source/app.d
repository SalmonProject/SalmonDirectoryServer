import vibe.d;

import client_censorproof_comm;
import client_db_logic;
import server;
import utility;
//import stringtypes;

import std.random;

import need_server;




shared static this()
{	
	
	dbClient = connectMongoDB("127.0.0.1");

	sslctx = createSSLContext(SSLContextKind.server);
	sslctx.useCertificateChainFile("salmon_dirserv.crt");
	sslctx.usePrivateKeyFile("salmon_dirserv.key");

	//logInfo(noSalmonButVPNGateServers());
	
	//when wanting to update udp_server: uncomment next line, ./dub, ctrl-c, mv directory_server udp_server
	//UDPserver();
	
/+
Here is what is going on here:
this "hack hack tcp process" variable is for the purpose of splitting up the server.
vibe.d is not very good at concurrency - sometimes something (i think a TCP connection?
still not really sure) hangs, which prevents the other parts of the program from processing
HTTP requests, reading the send_mail program's stdout, or getting UDP packets.
SO!
I just split the TCP and HTTP parts off. The HTTP part is its own (tiny bit of) code now,
since it's really simple and won't change much. However, the TCP- and email-based components
both use much of the same logic, so i want them together.
SO! WHAT IS GOING ON HERE?
We are no longer directly calling dub to compile+run. Now we have the script runsplit.sh.
That script first ensures that the variable is false (so the email+UDP part will run),
then uses nohup to call ./dub, then sleep 10 to let dub finish, then set to true and nohup dub again.
What a deliciously messy HACK!
+/
	const bool HACKHACK_TCP_PROCESS = true;
	static if(!HACKHACK_TCP_PROCESS)
	{
		auto router = new URLRouter;

		auto settings = new HTTPServerSettings;
		settings.port = 9004;
		settings.bindAddresses = ["127.0.0.1"];
		listenHTTP(settings, router);

		router.registerRestInterface(new defi);
		
		logError("Started email monitor, REST listener on 9004.");
	}
	else
	{
		listenTCP(cast(ushort)8080,
		(con)
		{
			try
			{
				//NOTE since we're a nice async task in here, a longer timeout is fine
				con.readTimeout = dur!"seconds"(15);
				SSLStream theSSL = createSSLStream(con, sslctx);
				CmdAndHash cmdHash = authenticateGetCommand(theSSL, null);

				if(cmdHash.command=='r')
					registerServer(theSSL, cmdHash.hash, ughIPv4StringFromVibe(con));
				else if(cmdHash.command=='d')//VPN server saying it's going down
					serverDown(theSSL, cmdHash.hash, ughIPv4StringFromVibe(con));
				else if(cmdHash.command=='u')//VPN server saying it's coming up
					serverUp(theSSL, cmdHash.hash, ughIPv4StringFromVibe(con));
				else if(cmdHash.command=='g')//VPN server giving us a usage report
					usageReport(theSSL, cmdHash.hash);
				else if(cmdHash.command=='A')//admin console
				{
					con.readTimeout = dur!"days"(20);
					adminConsole(theSSL, ughIPv4StringFromVibe(con));
				}
				else if(cmdHash.command=='?')
				{
					logInfo("****************************************");
					logInfo(niceCurTime()~": FAILED ADMIN LOGIN ATTEMPT from " ~ ughIPv4StringFromVibe(con));
					logInfo("****************************************");
				}
				
				theSSL.flush();
				theSSL.finalize();
				con.close();
				
			}
			catch(Exception e)
			{
				logError("\n===============================\n"~niceCurTime()~
				": "~ughIPv4StringFromVibe(con) ~ 
				" made a failed connection to our TCP port 8080: exception text "
				~to!string(e)~"\n===============================\n\n\n"); throw e;
			}
			//NOTE it's ok to ignore graceful SSL shutdown; there isn't anything
			//bad an adversary can do to us here by shutting it off early
		});
	}
}


void adminConsole(SSLStream theSSL, string fromIP)
{
	logInfo("****************************************");
	logInfo(niceCurTime()~": ADMIN SESSION STARTED FROM " ~ fromIP);
	logInfo("****************************************");
	
	
	char choiceAsChar;
	string stringToSend = "(n)otify all servers, add (r)ec code or (R)emove rec code, set user (t)rust, "~
	"(p)urge or un(P)urge server, (b)an user, (q)uit, (w)ipe WHOLE DB\n";
	do
	{
		theSSL.write(stringToSend);
		stringToSend = "(n)otify all servers, add (r)ec code or (R)emove rec code, set user (t)rust, "~
		"(p)urge or un(P)urge server, (b)an user, (q)uit\n";
		
		string choiceAsString = vibedTCPreadString(theSSL);
		choiceAsChar = choiceAsString[0];
		
		if(choiceAsChar=='n')
		{
			theSSL.write("Enter string to notify with: ");
			string notifyString = vibedTCPreadString(theSSL);
			logInfo("WOULD NOTIFY WITH "~notifyString);
		}
		else if(choiceAsChar=='r')
		{
			auto rCol = dbClient.getCollection(recCodesCollection);
			
			//generate a new code. make sure this code isn't already active, juuuust in case.
			char[] theCode;
			do
			{
				theCode = [];
				for(int i=0; i<7; i++)
					theCode ~= validChars[uniform(0, validChars.length)];
			} while(rCol.count(["recommendation": Bson(to!string(theCode))]) > 0);
			
			rCol.insert(Bson
			([
				"recommendation": Bson(to!string(theCode)),
				"recommender": Bson("asalmontester@hotmail.com"),
				"go_to_level": Bson(MAX_TRUST)
			]));
			
			stringToSend = theCode.idup~"\n"~stringToSend;
		}
		else if(choiceAsChar=='R')
		{
			theSSL.write("Enter code to be removed: ");
			string codeToRemove = vibedTCPreadString(theSSL).chomp();
			logInfo("Code to remove[["~codeToRemove~"]]");
			
			dbClient.getCollection(recCodesCollection).remove(["recommendation": Bson(codeToRemove)]);
		}
		else if(choiceAsChar=='t')
		{
			theSSL.write("Enter user email whose trust should be set: ");
			string whichUser = vibedTCPreadString(theSSL).chomp();
			theSSL.write("Enter trust level to set to: ");
			int whatTrust = to!int(vibedTCPreadString(theSSL).chomp());
			
			dbClient.getCollection(clientCollection).update(
				["email": Bson(whichUser)],["$set": ["trust": Bson(whatTrust)]]);
		}
		else if(choiceAsChar=='b')
		{
			theSSL.write("Enter email to ban: ");
			string whichUser = vibedTCPreadString(theSSL).chomp();
			ban(whichUser);
		}
		else if(choiceAsChar=='w')
		{
			theSSL.write("Are you sure you want to wipe THE WHOLE DATABASE? Type wannawipe: ");
			string shouldWipe = vibedTCPreadString(theSSL).chomp();
			if(shouldWipe.indexOf("wannawipe")==0)
			{
				dbClient.getCollection(serverCollection).remove();
        			dbClient.getCollection(clientCollection).remove();
        			dbClient.getCollection(groupCollection).remove();
        			dbClient.getCollection(recCodesCollection).remove();
			}
		}
		else if(choiceAsChar=='P')
		{
			theSSL.write("Enter server IP address to stop purging: ");
			string whichServer = vibedTCPreadString(theSSL).chomp();
			totallyUnpurgeServer(whichServer);
		}
		else if(choiceAsChar!='q')
			stringToSend = "Invalid command.\n"~stringToSend;
	}while(choiceAsChar!='q');
}
