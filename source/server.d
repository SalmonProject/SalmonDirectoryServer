module server;

import std.process;
import std.random;
import std.digest.sha;

import vibe.d;
import client_db_logic;
import need_server;
import utility;
//import stringtypes;

const static ushort listenOnThisUDPPort = 3389;
const ushort wrapperPort = 7004;
//the server's password with us
const int PASSWORD_LENGTH = 64;

//the users' "base" passwords; each user has one
const int VPN_BASE_PW_LENGTH = 64;
//the derived passwords: gotten from sha1(base_pw, server_ip)
const int VPN_DERIVED_PW_LENGTH = 20;


/++++++++++++++++++++++++++++++
===============================
DIR => WRAPPER MESSAGES
===============================
++++++++++++++++++++++++++++++/


//when a client claims a server is down, the client handler logic can call this to check
bool areYouStillThere(string passHash)
{
	auto sCol = dbClient.getCollection(serverCollection);
	auto results = sCol.find(["password_hash": Bson(passHash)]);
	string curIP;
	if(results.empty())
	{
		logError("AYST false: passHash "~passHash~" not found");
		return false;
	}

	foreach(doc ; results)
	{
		//if we think they're not online, no reason to expect them to have come back without telling us
		if(to!bool(doc["is_online"]) == false)
			return false;
		curIP = extractVibeString(doc["current_ip"]);
		break; //there should only be 1, so whatever
	}
	
	SSLStream theSSL = connectAndVerifySSL(curIP, wrapperPort, passHash);
	if(theSSL is null)
	{
		logError("AYST false: connectAndVerifySSL failed");
		markServerDown(passHash, sCol);
		return false;
	}
	else
	
	try 
	{
		theSSL.write("p");
	}
	catch(Exception e)
	{
		logError("AYST false: sending 'p' failed: "~to!string(e));
		markServerDown(passHash, sCol);
		return false;
	}
	
	string[] serverResponse = readLinesTLS(theSSL);
	
	if(serverResponse is null)
	{
		markServerDown(passHash, sCol);
		try{theSSL.finalize();}catch(Exception e){}
		logError("AYST false: got a null response");
		return false;
	}
	
	if(serverResponse[0].chomp()=="up")
	{
		int offered_bandwidth = to!int(serverResponse[1]);
		sCol.update
		([
			"password_hash": Bson(passHash)
		],[
			"$set": [	"offered_bandwidth": Bson(offered_bandwidth),
					 "estimated_start": Bson(serverResponse[2]),
					 "estimated_stop": Bson(serverResponse[3]),
					 "last_seen": Bson(BsonDate.fromString(Clock.currTime().toISOExtString())),
					"is_online": Bson(true)
		]]);
		//NOTE ah! this is why the wrapper was hanging: we weren't saying OK back to it!
		try
		{
			theSSL.write("OK");
			theSSL.finalize();
		}
		catch(Exception e)
		{
			logError("a server didn't wait for our OK to hang up from areYouStillThere, but whatevs.");
		}
		return true;
	}
	else
	{
		markServerDown(passHash, sCol);
		try{theSSL.finalize();}catch(Exception e){}
		logError("AYST false: got a response other than 'up': "~to!string(serverResponse));
		return false;
	}
}

//quick check that there is [something that looks like; it's actually softether] 
//an HTTPS server on port 443, which will correctly return a 404 in response to GET /index.html.
bool checkHTTPS(string theAddr)
{
	ProcessPipes checkHTTPS_Pipes = pipeProcess(["/home/fred/salmon/check_https/check_https",theAddr],
									    Redirect.stdout);
	scope(exit)
	{
		wait(checkHTTPS_Pipes.pid);
	}
	
	char[] readlnBuf;
	
	checkHTTPS_Pipes.stdout.readln(readlnBuf);
	return (readlnBuf.indexOf("HAI")>=0);
}

//TODO hmm..... what if they put a bunch of volunteers in the system, who do the exact same blocking 
//that they do? well, that's what the "force request new server" can be for.
//ask a server to check if it's blocked in country (true = blocked)
struct BlockStatus
{
	bool blocked;
	bool offline;
	string responseString;
}
BlockStatus requestBlockCheck(string passHash, bool clientReportedError, 
						string userEmail, string userBasePW, string country)
{
	auto sCol = dbClient.getCollection(serverCollection);
	auto results = sCol.find(["password_hash": Bson(passHash)]);
	
	logInfo(niceCurTime()~": block checking "~passHash~" for "~country);
	logError(niceCurTime()~": block checking "~passHash~" for "~country);
	
	bool wasOnline = false;
	bool curBlocked = false;
	bool foundOne = false;
	string curIP;
	foreach(doc ; results)
	{
		foundOne = true;
		curIP = extractVibeString(doc["current_ip"]);
		
		if(!doc["blocked_in"].isNull())
			foreach(thingy ; doc["blocked_in"])
			{
				string curBlockedIn = extractVibeString(thingy);
				if(curBlockedIn == country)
					curBlocked = true;
			}
			
		//if is_online is false (last we knew it was offline) AND clientReportedError is false (when
		//the client HTTPS GET'd just now, even that didn't work), then we can fairly safely save some
		//time and just assume the server is down.
		wasOnline = to!bool(doc["is_online"]);
		
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
		throw new Exception("Tried to block-check ("~country~") a non-existent server!");
	
	BlockStatus toRet;
	//default return value: "no change in block status, and server appears fully (i.e. no HTTPS) offline"
	toRet.blocked = curBlocked;
	toRet.offline = true;
	toRet.responseString = null;
	
	//see comment right above declaration of bool wasOnline.
	if(!wasOnline && !clientReportedError)
		return toRet;
	
	SSLStream theSSL = connectAndVerifySSL(curIP, wrapperPort, passHash);
	if(theSSL is null)
	{
		logError("requestBlockCheck connectAndVerifySSL failed.");
		markServerDown(passHash, sCol);
		return toRet;
	}
	
	try
	{
		theSSL.write("b"~country~"^"~deriveUsername(userBasePW, curIP));
	}
	catch(Exception e)
	{
		logError("requestBlockCheck send stuff failed.");
		markServerDown(passHash, sCol);
		return toRet;
	}
	
	string[] serverResponse = readLinesTLS(theSSL);
	try{theSSL.finalize();}catch(Exception e){}
	
	//softether should always return a nice 404 on any HTTPS GET to port 443.
	bool httpsUP = checkHTTPS(curIP);
	
	if(serverResponse is null || !httpsUP)
		markServerDown(passHash, sCol);
	else if(serverResponse[0].chomp() == "blocked")
	{
		//clientReportedError=true means the client succeeded with HTTPS GET but not connect.
		//so, assume the trouble is on the client's end, but is not a block. but DEFINITELY
		//don't report the server as being offline! the needServer logic considers this case "online".
		//in fact, since the trouble is on the client's end, let's override and return this server's
		//info, to try to overwrite the client's probably-faulty connection setting!
		if(clientReportedError)
		{
			toRet.offline = false;
			auto needBwAndCert = sCol.find(["password_hash": Bson(passHash)]);
			int offeredBW;
			string serverCert;
			string serverPSK;
			foreach(bwcert ; needBwAndCert)
			{
				offeredBW = to!int(bwcert["offered_bandwidth"]);
				serverCert = extractVibeString(bwcert["server_cert"]);
				serverPSK = extractVibeString(bwcert["psk"]);
				break;
			}
			toRet.responseString = generateNeedServerResponse(curIP, serverPSK, offeredBW, serverCert);
			return toRet;
		}
		else
		{
			logInfo(niceCurTime()~": "~passHash~"appears truly blocked in "~country);
			logError(niceCurTime()~": "~passHash~"appears truly blocked in "~country);
	
			markServerUp(passHash, sCol);
			sCol.update
			([
				"password_hash": Bson(passHash)
			],[
				"$addToSet": ["blocked_in": Bson(country)
			]]);
			
			string notifyString = "Your Salmon VPN server's IP address appears to have been blocked in ";
			if(country=="CN")
				notifyString~="China ";
			else if(country=="IR")
				notifyString~="Iran ";
			else
				notifyString~="some country other than China or Iran. ";
			notifyString~=
"If possible, please follow these instructions to get a new IP address:

Instructions for a typical cable modem:
1) Unplug the power cord and router's ethernet cable from the modem.
2) Wait for about a minute.
3) Connect the modem to some other device via ethernet cable.
4) Power the modem back on, and wait a minute.
5) Power the modem off, wait a minute, and connect it to the router as it was
   at the beginning.
6) Power the modem back on.";
			
			notifyUser(passHash, notifyString);
			
			toRet.blocked = true;
			toRet.offline = false;
		}
	}
	
	//server says they didn't have a softether user entry for the account name we asked about.
	//in this case, do a pleaseAddCredentials and [override the rest of the needServer logic; just return]
	else if(serverResponse[0].chomp() == "didnthave")
	{
		logError("blockcheck got 'didnthave'");
		toRet.responseString = pleaseAddCredentials(passHash, userEmail);
	}
	
	//server just came online in the last 5 minutes; we will assume client tried before server was ready.
	//this case just gets treated as plain old offline.
	else if(serverResponse[0].chomp() == "wasdown")
	{
		logError("blockcheck got a wasdown");
		markServerDown(passHash, sCol);
	}
	
	else//something we didn't expect... just treat them as down.
	{
		logError("blockcheck got... ????? unknown response!");
		markServerDown(passHash, sCol);
	}
	
	return toRet;
}

string derivePassword(string basePW, string curIP)
{
	//NOTE password is expected to be exactly VPN_DERIVED_PW_LENGTH chars.
	ubyte[] hashOutRaw = sha1Of(basePW~curIP);
	char[] tempPW = [];
	for(int j=0;j<VPN_DERIVED_PW_LENGTH;j++)
		tempPW ~= cast(char) ('a' + hashOutRaw[j]%26);
	return tempPW.idup;
}

string deriveUsername(string basePW, string curIP)
{
	char[] curIP_altered = curIP.dup;
	for(int i=0; i<curIP_altered.length; i++)
		curIP_altered[i]++;
	
	ubyte[] hashOutRaw = sha1Of(basePW~(curIP_altered.idup));
	char[] tempPW = [];
	for(int j=0;j<VPN_DERIVED_PW_LENGTH;j++)
		tempPW ~= cast(char) ('a' + hashOutRaw[j]%26);
	return tempPW.idup;
}

/+dir is going to tell the wrapper "here are some new username/password credentials you should start
 accepting." each client has a (single) vpn_username and vpn_password entry, so this function just takes 
 a list of client emails, then looks those entries up, and sends the message. hooray!+/
/+will return a properly formatted message that can be directly returned to the client. (for convenience 
 and efficiency: we call this from needServer, and use this to build that message, since this function 
 is already querying the db for this server's record anyways)+/
//(NOTE RETURNED STRING FORMAT IS "ipaddr bw\nSERVERCERT---DSVASFSDFDS", just as the email protocol wants)
string pleaseAddCredentials(string passHash, string clientEmail)
{
	auto uCol = dbClient.getCollection(clientCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	
	auto results = sCol.find(["password_hash": Bson(passHash)]);
	bool foundOne = false;
	string curIP;
	int offeredBW;
	string serverCert;
	string serverPSK;
	foreach(doc ; results)
	{
		foundOne = true;
		curIP = extractVibeString(doc["current_ip"]);
		offeredBW = to!int(doc["offered_bandwidth"]);
		serverCert = extractVibeString(doc["server_cert"]);
		serverPSK = extractVibeString(doc["psk"]);
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
		return null;
	
	string clientBasePW;
	auto results2 = uCol.find(["email": Bson(clientEmail)]);
	foundOne = false;
	foreach(doc ; results2)
	{
		foundOne = true;
		clientBasePW = extractVibeString(doc["vpn_password"]);
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
	{
		logError("Warning! tried to tell "~curIP~" to add non-existent client: "~clientEmail);
		return null;
	}
	
	//NOTE NOTE NEW NEW NEW! :D    each user should have a different pw at every VPN. we can do that
	//		easily enough by just having the pass be sha1(basepw, serverIP).
	//NOTE EVEN NEWER: it's ridiculous to use email addrs here... just derive a second string for username.
	char[] theMessage;
	theMessage~=deriveUsername(clientBasePW, curIP)~"\n"~derivePassword(clientBasePW, curIP)~"\n";
	theMessage~="@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@";
	
	SSLStream theSSL = connectAndVerifySSL(curIP, wrapperPort, passHash);
	if(theSSL is null)
	{
		logError("pleaseAddCredentials connectAndVerifySSL failed.");
		markServerDown(passHash, sCol);
		return null;
	}
	
	try 
	{
		theSSL.write("c"~theMessage);//c for credentials
		theSSL.finalize();
	}
	catch(Exception e)
	{
		logError("pleaseAddCredentials send stuff / finalize failed.");
		markServerDown(passHash, sCol);
		return null;
	}
	
	
	//if the user we're giving this server to is currently purging the same IP address
	//that this server has, we should end the purge for that client.
	unpurgeServer(curIP, clientEmail);
	
	//TODO TODO HACK HACK HACK HACK HACK
	//TODO TODO HACK HACK HACK HACK HACK
	//TODO TODO HACK HACK HACK HACK HACK
	//yeah this is terrible... but, it looks like sometimes the client tries to connect 
	//to their new server before the server knows about them.
	sleep(5.seconds);//TODO TODO HACK HACK HACK HACK HACK
	//TODO TODO HACK HACK HACK HACK HACK
	//TODO TODO HACK HACK HACK HACK HACK
	//TODO TODO HACK HACK HACK HACK HACK
	
	//this is the message that goes back to the client
	return generateNeedServerResponse(curIP, serverPSK, offeredBW, serverCert);
}


void notifyUser(string passHash, string message)
{
	
	auto sCol = dbClient.getCollection(serverCollection);
	auto results = sCol.find(["password_hash": Bson(passHash)]);
	bool foundOne = false;
	string curIP;
	string notifyEmail = null;
	foreach(doc ; results)
	{
		foundOne = true;
		curIP = extractVibeString(doc["current_ip"]);
		if(!doc["notify_email"].isNull())
			notifyEmail = extractVibeString(doc["notify_email"]);
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
		return;
	
	
	SSLStream theSSL = connectAndVerifySSL(curIP, wrapperPort, passHash);
	if(theSSL is null)
	{
		logError("notifyUser connectAndVerifySSL failed.");
		markServerDown(passHash, sCol);
		return;
	}
	
	theSSL.write("n"~message);//n for notify
	try{theSSL.finalize();}catch(Exception e){}
	
	if(notifyEmail !is null)
		wait(spawnProcess(["/home/fred/salmon/vmime_dir_server/plain_send_mail", notifyEmail,
					   "\"Notification about Salmon VPN server\"", "\""~message~"\""]));
}



/++++++++++++++++++++++++++++++
===============================
WRAPPER => DIR MESSAGES
===============================
++++++++++++++++++++++++++++++/


//a new volunteer has joined. the first thing their wrapper does is send this registration message to us.
//it will have: (all of these are strings, including the numeric ones)
//offered bandwidth, in kilobytes per second
//estimated start (format: that ISOex or whatever, e.g. 2014-07-12T10:01:00) (but only time matters, not date)
//estimated stop (NOTE if these times weren't provided, just have these lines say NEVER)
//NOTE haha oh right, when you're doing this you don't have their password on file so you can't verify!
void registerServer(SSLStream ssl, string passHash, string peerAddress)
{try{

	string[] serverResponse = readLinesTLS(ssl);
	
	if(serverResponse is null || serverResponse.length < 6)
	{
		ssl.write("Malformed request; registration aborted. ");
		logInfo("Malformed request; registration aborted.");
		foreach(thestr ; serverResponse)
			logInfo(thestr);
		return;
	}
	
	bool probablyWindows = (serverResponse[0].indexOf(" ")>=0);
	
	string current_ip = peerAddress;
	string offeredBandwidth = strip(serverResponse[0]);
	string estStartString = strip(serverResponse[1]);
	string estStopString = strip(serverResponse[2]);
	string thePSK = strip(serverResponse[3]);
	string notifyEmail = strip(serverResponse[4]);
	string thisServerCert = "";
	for(int i=5; i<serverResponse.length; i++)
	{
		//had some issues with newlines, at some point between here and when the client extracts the 
		//base64'd cert out of the email. soooo, we're just going to encode \n's in the cert as *'s.
		thisServerCert ~= serverResponse[i].chomp() ~ "*";
	}
	
	BsonDate estimated_start = (estStartString == "NEVER" ? 
							BsonDate.fromString("2014-07-12T00:01:00") :
							 BsonDate.fromString(estStartString));
	BsonDate estimated_stop = (estStopString == "NEVER" ? 
							BsonDate.fromString("2014-07-12T23:59:00") :
							 BsonDate.fromString(estStopString));
	
	/+stop them from DoSing us with a bajillion server registrations
	you can't register if there is a server active *and currently online on your ip already*.
	allowing them to reregister when their IP has been used but the person isn't online makes sense.
	if the one on their IP is marked as online, areYouStillThere to confirm.+/
	auto sCol = dbClient.getCollection(serverCollection);
	
	bool anyOnline = false;
	bool anyFound = false;
	auto results = sCol.find(["current_ip": Bson(current_ip)]);
	string thisServerPH = null;
	foreach(doc ; results)
	{
		anyFound = true;
		thisServerPH = extractVibeString(doc["password_hash"]);
		if(areYouStillThere(thisServerPH))
		{
			anyOnline = true;
			break;
		}
	}

	if(anyOnline)
	{
		ssl.write("It looks like you, or someone on your IP address, is already in the system as a server, and is currently online. Registration failed. You can register if that other server goes offline.");
		return;
	}
	else if(anyFound)
	{
		//there WAS a server entry with this IP that wasn't online; remove it to make way for the new one.
		
		//first, remove the old server's entry from the servers collection, of course
		sCol.remove(["current_ip": Bson(current_ip)]);
		
		
		//but now! if it has been given to anyone, its passhash will be in some group's 'servers' array,
		//as well as in some user(s)'s 'servers_given' array: get the passhash out of those arrays.
		//NOTE (Can't have users' servers_given become IPs, because what if the server changes IPs?)
		auto gCol = dbClient.getCollection(groupCollection);
		gCol.update(["servers": Bson(thisServerPH)],
				  ["$pull": ["servers": Bson(thisServerPH)]]);
		
		auto uCol = dbClient.getCollection(clientCollection);
		uCol.update(["servers_given": Bson(thisServerPH)],
				  ["$pull": ["servers_given": Bson(thisServerPH)]]);
	}
	

	if(notifyEmail.indexOf("!#$%^NONE!#$%^")>=0) sCol.insert(Bson
	([
		"password_hash": Bson(passHash),
		"current_ip": Bson(current_ip),
		"offered_bandwidth": Bson(to!int(offeredBandwidth)),
		"estimated_start": Bson(estimated_start),
		"estimated_stop": Bson(estimated_stop),
		"is_online": Bson(false),
		"is_assigned": Bson(false),
		"server_cert": Bson(thisServerCert),
		"psk": Bson(thePSK),
		 "probably_windows": Bson(probablyWindows),
		"last_seen": Bson(BsonDate.fromString(Clock.currTime().toISOExtString())),
		"total_kbytes": Bson(to!long(0))//have to explicitly indicate we want a long
	]));
	else sCol.insert(Bson
	([
		"password_hash": Bson(passHash),
		"current_ip": Bson(current_ip),
		"offered_bandwidth": Bson(to!int(offeredBandwidth)),
		"estimated_start": Bson(estimated_start),
		"estimated_stop": Bson(estimated_stop),
		"is_online": Bson(false),
		"is_assigned": Bson(false),
		"server_cert": Bson(thisServerCert),
		"psk": Bson(thePSK),
		 "probably_windows": Bson(probablyWindows),
		"last_seen": Bson(BsonDate.fromString(Clock.currTime().toISOExtString())),
		"notify_email": Bson(notifyEmail),
		"total_kbytes": Bson(to!long(0))//have to explicitly indicate we want a long
	]));
	
	logInfo(niceCurTime()~": registered server at "~current_ip~
			" with passHash "~passHash[0..8]~"!");
	
	//NOTE don't need to do any assigning to levels or computing scores at this point. the offered bandwidth
	//and estimated start/stop times are enough; the logic in pickServerAtLevel is happy just using those.

	ssl.write("OK");

	
}catch(Exception e){logError("oh crap server reg failed with: "~to!string(e));}}



//tell the directory server that our VPN server is now accepting connections. this is also the 
//general purpose "update parameter" thing, like, if you have a new estimated up/down time, or ip addr.
//(basically, every possible parameter should be sent, and we just write those values into the db entry.)
void serverUp(SSLStream ssl, string passHash, string peerAddress)
{
	string[] serverResponse = readLinesTLS(ssl);
	if(serverResponse is null || serverResponse.length < 3)
	{
		//NOTE because of how we're doing things now, it's better to not do an error message,
		//and just have the fact of a closed connection indiciate the error
		//ssl.write("Malformed request; server-up aborted.");
		return;
	}
	
	//strip() is because windows server will give e.g. "123 ", which to!int doesn't like.
	int offered_bandwidth = to!int(strip(serverResponse[0]));
	string estStartString = strip(serverResponse[1]);
	string estStopString = strip(serverResponse[2]);
	
	BsonDate estimated_start = (estStartString == "NEVER" ? 
							BsonDate.fromString("2014-07-12T10:01:00") :
							 BsonDate.fromString(estStartString));
	BsonDate estimated_stop = (estStopString == "NEVER"? 
							BsonDate.fromString("2014-07-12T10:02:00") :
							 BsonDate.fromString(estStopString));
	
	logInfo(niceCurTime()~": server up bw is "~to!string(offered_bandwidth)~" and ip is "~peerAddress);
	
	auto sCol = dbClient.getCollection(serverCollection);
	
	//before we update, get their previous ip address, so that if they are currently blocked
	//we will know to do the "refresh" logic
	auto getIPresults = sCol.find(["password_hash": Bson(passHash)]);
	string oldIP;
	foreach(doc ; getIPresults)
		oldIP = extractVibeString(doc["current_ip"]);
	
	sCol.update
	([
		"password_hash": Bson(passHash)
	],[
		"$set": [	"current_ip": Bson(peerAddress),
				"offered_bandwidth": Bson(offered_bandwidth),
				"estimated_start": Bson(estimated_start),
				"estimated_stop": Bson(estimated_stop),
				"is_online": Bson(true),
				 "last_seen": Bson(BsonDate.fromString(Clock.currTime().toISOExtString()))
	]]);
	
	//look up all users that are currently supposed to have access to this server.
	//send all of their logins (email + vpn password) to the server.
	auto uCol = dbClient.getCollection(clientCollection);
	auto results = uCol.find(["servers_given": passHash]);
	string theMessage = "";
	foreach(doc ; results)
	{
		string curBasePW = extractVibeString(doc["vpn_password"]);
		theMessage~=	deriveUsername(curBasePW, peerAddress)~"\n"~
					derivePassword(curBasePW, peerAddress)~"\n";
	}
	theMessage~="@@@ENDLIST@@@@@@ENDLIST@@@@@@ENDLIST@@@";
	ssl.write(theMessage);
	
	
	//if this server is blocked somewhere, and this serverUp is indicating that it has a new
	//address, then initiate the "refresh" logic, whereby it essentially becomes a completely
	//new server, other than keeping the same password, and offered bandwidth/uptime.
	if(oldIP != peerAddress)
	{
		auto blockresults = sCol.find(["password_hash": Bson(passHash)]);
		foreach(doc ; blockresults)
		{if(!doc["blocked_in"].isNull())
		{
			//NOTE not currently possible; see below
			//foreach(thingy ; doc["blocked_in"])
				//check if they're still blocked there
			
			//NOTE ideally, here we would individually check if we're still blocked in each country.
			//	however, our logic only makes block checking possible when a client has come to us
			//	saying "i'm in this country and i think this server is blocked". so, instead just
			//	make them look like a brand new server (and have their group+users forget them):
			//	clear the server's blocked_in list, clear their group, pull their hash from user
			//	entries who have their hash in servers_given, and mark them unassigned. also make 
			//	their group forget about them. now they are definitely cut off from the users.
			
			if(!doc["group"].isNull())
			{
				Bson theOldGroup = doc["group"];
				auto gCol = dbClient.getCollection(groupCollection);
				gCol.update([
							"_id": theOldGroup
						],[
							"$pull": ["servers": Bson(passHash)]
						]);
			}
			
			uCol.update	([
							"servers_given": passHash
						],[
							"$pull": ["servers_given": Bson(passHash)]
						]);
			
			sCol.update([
						"password_hash": Bson(passHash)
					],[
						"$unset": ["blocked_in": Bson(""), "group": Bson("")],
							"$set": ["is_assigned": Bson(false)]
					]);
		}}
	}
}

void serverDown(SSLStream ssl, string passHash, string peerAddress)
{
	dbClient.getCollection(serverCollection).update
	([
		"password_hash": Bson(passHash)
	],[
		"$set": [	"current_ip": Bson(peerAddress),
				"is_online": Bson(false)
	]]);
}

//keep track of the last UDP packet we got from this ip address. if the last one was
//less than 2 minutes ago, don't even bother with the mongo find etc, just ignore.
SysTime[string] UDPdowns;
//ok so.... i think maybe it's just because this computer got its time zone set to UTC or something,
//but the UDP down has stopped working because the clocks don't line up. so i guess let's instead just
//do a logical clock thing: they can report whatever time they want, but it has to be always increasing.
//replay is still defended against: you can't construct a new hash with a higher time without knowing the pw.
SysTime[string] theirClocks;

//buf format should be: (64bit)seconds since epoch, sha1(sse,base64(pass))
void serverDownUDP(ubyte[] buf, NetworkAddress packetFrom)
{
	string theIPAddr;
	if(to!string(packetFrom).indexOf(":") > 0)
		theIPAddr = to!string(packetFrom)[0..to!string(packetFrom).indexOf(":")];
	else
		theIPAddr = to!string(packetFrom);
	
	
	//NOTE NOTE sort-of-HACK: directory server is expected to always be on a 64-bit little endian system!
	version(X86){static assert(false, "TIME HAS TO BE 64 BITS, SO 64-BIT CPUs ONLY PLEASE");}
	version(BigEndian){static assert(false, "DIR SERVER CAN ONLY RUN ON LITTLE ENDIAN SYSTEMS");}
	
	//check the time: NOTE OLD: should be no more than 30s old
	//			NOTE current: should be greater than their previous reported time value.
	
	ulong* pointToTime = cast(ulong*)buf.ptr;
	ubyte[8] littleEndianTime;
	for(int i=0;i<8;i++)
		littleEndianTime[i] = buf[7-i];
	ulong* leTimePtr = cast(ulong*)littleEndianTime.ptr;
	SysTime theirCurClock = SysTime(unixTimeToStdTime(*leTimePtr));
	
	if(theIPAddr in theirClocks && theirClocks[theIPAddr] >= theirCurClock)
	{
		logInfo("IP "~theIPAddr~" has a theirClocks entry geq reported value. "~
				"If you see two of these after one successful UDP-down, it's normal.");
		return;
	}
	
	//don't let them make us do a bajillion Mongo finds per second with only UDP packets
	//NOTE still need to do this even with the logical clock thing, because they can report
	//whatever logical clock despite not being able to make the hash match: if we didn't do
	//this check, they would be able to do the mongo find dos.
	if(theIPAddr in UDPdowns && UDPdowns[theIPAddr]+dur!"minutes"(2) > Clock.currTime())
	{
		//actually there is still a DoS vulnerability here if we even just log this message...
		logInfo("IP "~theIPAddr~" send a down message too soon after previous one. "~
				"If you see two of these after one successful UDP-down, it's normal.");
		logInfo("UDP server down came too soon after previous one for this server. UDPdowns[IP]: "
				~to!string(UDPdowns[theIPAddr])~", Clock.currTime(): "~niceCurTime());
		return;
	}
	
	UDPdowns[theIPAddr] = Clock.currTime();
	
	//look up the IP address we received from in servers db
	auto sCol = dbClient.getCollection(serverCollection);
	
	auto results = sCol.find
	([
		"current_ip": Bson(theIPAddr)
	]);
	string base64PW;
	foreach(doc ; results)
	{
		base64PW = extractVibeString(doc["password_hash"]);
		break;
	}
	
	//check the hash: corresponding password should be able to give same hash
	//NOTE woooo this works exactly as i hoped it would!!!!!!!
	if(buf[8..28] == sha1Of(buf[0..8]~cast(ubyte[])base64PW))
	{
		//now that hash is verified, it's safe to update their logical clock.
		theirClocks[theIPAddr] = theirCurClock;
		logInfo("*************\nValid UDP server-down ("~theIPAddr~")!!!\n*************");
		markServerDown(base64PW, sCol);
	}
	else
	{
		logInfo(niceCurTime()~
		": weird... got a UDP-down message with a wrong hash. (Or just not in our format.)");
		logInfo("received: "~to!string(buf));
		logInfo("hash input: "~to!string(buf[0..8]~cast(ubyte[])base64PW));
		logInfo("hash output: "~to!string(cast(ubyte[])sha1Of(buf[0..8]~cast(ubyte[])base64PW)));
		logInfo("their buf 8..$: "~to!string(buf[8..$]));
	}
}

//server reporting how much / how real looking traffic its users are sending
//NOTE turns out this one is going to be pretty important... this is where we check
//whether a client's score has earned it a promotion yet, and then do all the fancy
//"what group do we put them in" n-ary search logic
void usageReport(SSLStream ssl, string passHash)
{
	string[] serverResponse = readLinesTLS(ssl);
	//just ignore it if it isn't sent correctly
	if(serverResponse is null)
		return;
	
	logInfo("got usage report");
	
	auto uCol = dbClient.getCollection(clientCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	auto gCol = dbClient.getCollection(groupCollection);
	
	//UGGGGHHHH now that the servers aren't using client email addresses... 
	//instead, now need to take the server's group (after ensuring it has one), and for each user in
	//that group, derive the username to check against what the server reported.
	//examine the client's entry to be sure server should be reporting on it, then extract its info.
	//retrieve server's group
	auto thisServRes = sCol.find(["password_hash": Bson(passHash)]);
	Bson thisServGroupID;
	string servIP;
	
	foreach(loldoc ; thisServRes)
	{
		if(loldoc["group"].isNull())
		{
			logInfo("ERROR! Server "~passHash~" is trying to report when it doesn't even have a group.");
			return;
		}
		thisServGroupID = loldoc["group"];
		servIP = extractVibeString(loldoc["current_ip"]);
		break;
	}
	
	struct stringAndPW
	{
		string email;
		string pw;
	}
	auto getGroupRes = gCol.find(["_id": thisServGroupID]);
	stringAndPW[] servGrpUserList;
	foreach(lol2doc ; getGroupRes)
	{
		Bson[] userIDs;
		if(!lol2doc["users"].isNull())
			foreach(thingy ; lol2doc["users"])
				userIDs ~= thingy;
		
		foreach(id ; userIDs)
		{
			auto wow = uCol.find(["_id": id]);
			foreach(such ; wow)
			{
				stringAndPW very;
				very.email = extractVibeString(such["email"]); //wow
				very.pw = extractVibeString(such["vpn_password"]);
				servGrpUserList ~= very;
			}
		}
	}
	
	
	//NOTE we have the "usage_score_last_applied" to prevent servers from boosting clients way up.
	//HOWEVER. clients can have multiple servers... if they're only using one, and another one reports 
	//a score of 0 before the one being used reports a good score, we'll need to let the better one 
	//overwrite the worse one.
	//the logic for that:
	//examine the client's entry.
	//if it's been a day since they've been reported on
		//update the usage_score_last_applied field
		//add the reported score to usage_score
		//set last_usage_value to the current one.
	//else it has been less than a day
		//(leave usage_score_last_applied alone)
		//if the reported score > last highest reported score (called last_usage_value)
			//add the difference of those to usage_score
			//set last_usage_value to the reported value
	
	//NOTE format: a variable number of lines, with each line being:
	//[email of client]:..@..:[that client's score]  (e.g. example@hotmail.com:..@..:34)
	//NOTE :..@..: is the delimiter because i'm quite sure it's impossible for a valid email address to have
	//for each user reported on, add on that score, and do the promotion logic if earned
	foreach(curLine ; serverResponse)
	{
		//final line is server's total bytes, marked by this prefix. read the number and then we're done.
		if(curLine.indexOf(":.bw.@.bw.:") >= 0)
		{
			version(X86)
			{
				uint kBytesStart = curLine.indexOf(":.bw.@.bw.:")+11;
			}
			else
			{
				long kBytesStart = curLine.indexOf(":.bw.@.bw.:")+11;
			}
			string totalKBytes = curLine[kBytesStart..$].idup;
			logInfo("TOTAL KBYTES:"~totalKBytes);
			
			auto servRes = sCol.find(["password_hash": Bson(passHash)]);
			foreach(doc ; servRes)
			{
				if(to!long(totalKBytes) > to!long(doc["total_kbytes"]))
					sCol.update(["password_hash": Bson(passHash)],
							  ["$set" : ["total_kbytes": Bson(to!long(totalKBytes))]]);
				break;
			}
			break;
		}
		
		string curUsername;
		version(X86)
		{
			uint delimIndex = curLine.indexOf(":..@..:");
			uint afterDelim = delimIndex+7;
		}
		else
		{
			long delimIndex = curLine.indexOf(":..@..:");
			long afterDelim = delimIndex+7;
		}
		if(delimIndex<4 || !isNumeric(curLine[afterDelim..$]) || indexOf(curLine[afterDelim..$], ".") >=0 ||
			to!int(curLine[afterDelim..$]) < 0 || to!int(curLine[afterDelim..$]) > MAX_DAILY_SCORE)
		{
			logInfo("Server "~passHash~" sent malformed usage report line: "~curLine);
			continue;
		}
		curUsername = curLine[0..delimIndex].idup;
		ushort dailyScore = to!ushort(curLine[afterDelim..$]);
		
		//UGGGGHHHH now that the servers aren't using client email addresses... 
		//instead, now need to take the server's group (after ensuring it has one), and for each user in
		//that group, derive the username to check against what the server reported.
		//examine the client's entry to be sure server should be reporting on it, then extract its info.
		string foundEmail = cast(string)null;
		//foreach client in group
			//check if it derives to curUsername (complain if none do)
				//if yes, foundEmail = this client's email
		foreach(user ; servGrpUserList)
		{
			if(curUsername == deriveUsername(user.pw, servIP))
			{
				foundEmail = user.email;
				break;
			}
		}
		if(foundEmail is null)
		{
			logInfo("Server "~passHash~": you are not supposed to be reporting on client "~foundEmail);
			continue;
		}
		
		auto results = uCol.find(["email": Bson(foundEmail)]);
		bool foundOne = false;
		bool serverHasClient = false;
		int uScore;
		ushort lastScoreAdded;
		SysTime lastApplication;
		short trustLevel;
		double suspicionComplementCN;
		double suspicionComplementIR;
		
		foreach(doc ; results)
		{
			foundOne = true; 
			foreach(docElement ; doc["servers_given"])
				if(passHash == extractVibeString(docElement))
				{
					serverHasClient = true;
					break;
				}
			
			//NOTE this should never happen, but let's be defensive since this might otherwise crash us.
			if(doc["usage_score"].isNull() || doc["last_usage_value"].isNull() ||
				doc["usage_score_last_applied"].isNull() || doc["trust"].isNull() ||
				doc["suspicion_complement_CN"].isNull() || doc["suspicion_complement_IR"].isNull())
			{
				uCol.update
				([
					"email": Bson(foundEmail)
				],[
					"$set": ["usage_score": Bson(0),
							"last_usage_value": Bson(0),
							 "usage_score_last_applied": 
							 Bson(BsonDate.fromString("2002-02-02T10:01:00")),
							 "trust": Bson(1 - NEG_MAX),
							 "suspicion_complement_CN": Bson(0.5),
							 "suspicion_complement_IR": Bson(0.5)
					]
				]);
			}
			
			uScore = to!int(doc["usage_score"]);
			lastScoreAdded = cast(ushort)to!int(doc["last_usage_value"]);
			lastApplication = (cast(BsonDate)doc["usage_score_last_applied"]).toSysTime();
			trustLevel = cast(short)to!int(doc["trust"]);
			suspicionComplementCN = to!double(doc["suspicion_complement_CN"]);
			suspicionComplementIR = to!double(doc["suspicion_complement_IR"]);
			break;
		}
		if(!foundOne || !serverHasClient)
		{
			logInfo("Server "~passHash~": you are not supposed to be reporting on client "~foundEmail);
			continue;
		}
		
		//ok, it's a valid report. do the logic.
		
		//if it's been a day since the user's usage has been reported on
		if(Clock.currTime() - lastApplication > dur!"days"(1))
		{
			//update the usage_score_last_applied field, add the reported score to usage_score, 
			//and set last_usage_value to the score being reported.
			//also, reduce suspicion by (score/200) percentage points.
			uCol.update
			([
				"email": Bson(foundEmail)
			],[
				"$set": ["last_usage_value": Bson(dailyScore),
						 "usage_score_last_applied":
						  Bson(BsonDate.fromString(Clock.currTime().toISOExtString()))
						  /+NOTE the to-from string might be unnecessary, but i'm not sure what vibe's
						  fromStdTime is supposed to be, and this version was tested and works (see
						  advanced_bson_examples)+/
				],
				"$inc": ["usage_score": Bson(dailyScore)]
			]);
			uScore += dailyScore;
		}
		else //it has been less than a day
		{
			//leave usage_score_last_applied alone
			//if reported dailyScore > the highest one that has been reported so far today
			//also, reduce suspicion by (increase in score/200) percentage points.
			if(dailyScore > lastScoreAdded)
			{
				//add the difference of reported value and last_usage_value to usage_score
				//set last_usage_value to the value being reported.
				uCol.update
				([
					"email": Bson(foundEmail)
				],[
					"$set": ["last_usage_value": Bson(dailyScore)],
					"$inc": ["usage_score": Bson(dailyScore-lastScoreAdded)]
				]);
				uScore += dailyScore-lastScoreAdded;
			}
		}
		//NOTE this function asks for SUSPICION, NOT complement of suspicion. also, pretty sure the most
		//sensible approach is to give it the max of all suspicions.
		checkAndApplyPromotion(foundEmail, trustLevel, uScore, 
						   (1-suspicionComplementCN) > (1-suspicionComplementIR) ? 
						   (1-suspicionComplementCN) : (1-suspicionComplementIR));
	}
}



TCPConnection connectTCPTimeout(Duration timeout, string host, ushort port, bool suppressErrors = false)
{
	TCPConnection conn;
	Exception ex = null;
	auto connect_task = runTask
	({
		try conn = connectTCP(host, port);
		catch (Exception e) { ex = e; }
	});
	//logInfo("started TCP connection timer at: "~niceCurTime());
	auto tm = setTimer(timeout, { connect_task.interrupt(); logError("TCP connection timer timed out at: "~niceCurTime());});
	connect_task.join();
	tm.stop();
	if (ex !is null)
	{
		//throw ex;
		if(!suppressErrors)
			logError("something inside connectTCPTimeout threw: "~to!string(ex));
		return null;
	}
	if(!conn.connected)
	{
		if(!suppressErrors)
			logError("connectTCPTimeout wound up with a non-connected TCPConnection.");
		return null;
	}
	return conn;
}



/++++++++++++++++++++++++++++++
===============================
UTILITIES
===============================
++++++++++++++++++++++++++++++/

void UDPserver()
{
	ubyte[] buf = new ubyte[100];
	auto udpServer = listenUDP(listenOnThisUDPPort);
	logInfo("started UDP listener on port "~to!string(listenOnThisUDPPort));
	while(1)
	{
		try
		{
			NetworkAddress packetFrom;
			//udpServer.recv(dur!"msecs"(50), buf, &packetFrom);
			//now that we have the UDP server running as its own process, we can just block, and
			//these timeout exceptions were what was causing the memory leak i guess?
			udpServer.recv(buf, &packetFrom);
			serverDownUDP(buf, packetFrom);
		}
		catch(Exception e){}
	}
}

void markServerDown(string passHash, MongoCollection col)
{
	//logInfo("before server down mongo update");
	col.update(["password_hash": Bson(passHash)],["$set": ["is_online": Bson(false)]]);
	//logInfo("after the server down mongo update");
}

void markServerUp(string passHash, MongoCollection col)
{
	col.update(["password_hash": Bson(passHash)],["$set": 
			[
				"is_online": Bson(true),
				"last_seen": Bson(BsonDate.fromString(Clock.currTime().toISOExtString()))
			]]);
}

void unpurgeServer(string serverIP, string userEmail)
{
	dbClient.getCollection(clientCollection).update(
			[
				//NOTE TO SELF: yes, this implicit syntax means "and".
				"email": userEmail,
				"purge_list": serverIP
			],
			["$pull": ["purge_list": serverIP]]);
}

//remove this ip from any user's purge list that has it
void totallyUnpurgeServer(string serverIP)
{
	dbClient.getCollection(clientCollection).update(
			//NOTE NOTE TODO oh wait, i think $in isn't necessary here? 
			//it actually means "find any of these", and for finding something 
			//"in" an array, you just give the thing you want?
			["purge_list": serverIP],
			["$pull": ["purge_list": serverIP]]);
}


void purgeServer(string serverIP)
{
	/++
	look up server by ip
	find any user who has that pass hash and:
		remove the pass hash from them
		add the IP address to that user's purge_list ($addToSet !)
			whenever they needServer, they are told about the purge
			//NOTE populating this list of "users who are purging the server" right now, and then relying
			//only on this list works nicely: if the server comes online later while we're still purging 
			//it, it can get new users without them being told to purge it (it isn't in their list).
	find any group that has that pass hash and remove the pass hash from that group
	remove the pass hash from the server db+/
	
	auto sCol = dbClient.getCollection(serverCollection);
	auto uCol = dbClient.getCollection(clientCollection);
	auto gCol = dbClient.getCollection(groupCollection);
	
	auto results = sCol.find(["current_ip": serverIP]);
	foreach(doc ; results)
	{
		string curPassHash = extractVibeString(doc["password_hash"]);
		uCol.update(	["servers_given": curPassHash],
					[
						"$pull": ["servers_given": curPassHash],
						"$addToSet": ["purge_list": serverIP]
					]);
		
		gCol.update(	["servers": curPassHash],
					[
						"$pull": ["servers": curPassHash]
					]);
	}
	sCol.remove(["current_ip": serverIP]);
	
	
	//done in pleaseAddCredentials: if a user is assigned a new server, 
	//stop them purging it if they are (remove it from purge_list)
}

SSLStream connectAndVerifySSL(string curIP, ushort port, string passHash)
{
	TCPConnection con;
	
	try
	{
		con = connectTCPTimeout(3.seconds, curIP, port);
	}
	catch(Exception e)
	{
		logError("ok, connectAndVerifySSL's connectTCPTimeout throwing: "~to!string(e));
		//throw new Exception("TCP connection to "~curIP~" timed out... or "~to!string(e));
		return null;
	}
	if(con is null)
	{
		logError("connectTCPTimeout returned null");
		return null;
	}

	con.readTimeout = dur!"seconds"(3);
	if(!con.connected)
	{
		//throw new Exception("(SHOULDNT BE HERE?) Could not make a TCP connection to "~curIP);
		logError("(SHOULDNT BE HERE?) Could not make a TCP connection to "~curIP);
		return null;
	}
	
	SSLContext serv_sslctx = createSSLContext(SSLContextKind.server);
	serv_sslctx.useCertificateChainFile("salmon_dirserv.crt");
	serv_sslctx.usePrivateKeyFile("salmon_dirserv.key");
	
	SSLStream theSSL = null;
	try
	{
		theSSL = createSSLStream(con, serv_sslctx);
	}
	catch(Exception e)
	{
		logError("createSSLStream throwing: "~to!string(e));
		try{con.close();}catch(Exception lel){}
		return null;
	}
	CmdAndHash cmdRet;
	try
	{
		cmdRet = authenticateGetCommand(theSSL, passHash);
	}
	catch(Exception e)
	{
		logError("authenticateGetCommand throwing: "~to!string(e));
		try{theSSL.finalize();}catch(Exception lel){}
		try{con.close();}catch(Exception lel){}
		return null;
	}
	
	//NOTE the "hash is correct" check is also done inside authenticate
	if(cmdRet.command !='z' || cmdRet.hash != passHash)
	{
		try{theSSL.finalize();}catch(Exception lel){}
		try{con.close();}catch(Exception lel){}
		//OLD NOTE it's ok that this is an exception. this function is always called inside a try.
		if(cmdRet.command =='!' || cmdRet.hash != passHash)
		{
			//throw new Exception(curIP~": password did not match expected hash!");
			logInfo(curIP~": password did not match expected hash!");
			return null;
		}
		else
		{
			//throw new Exception(curIP~": client did not say 'z' to us!");
			logInfo(curIP~": client did not say 'z' to us!");
			return null;
		}
	}
	return theSSL;
}

struct CmdAndHash
{
	char command;
	string hash;
}
CmdAndHash authenticateGetCommand(SSLStream theSSL, string rightHash)
{
	CmdAndHash ret;

	//first read their password. they will always send that first, and it's a fixed length.
	ubyte[PASSWORD_LENGTH] recvBuf;
	theSSL.read(recvBuf);
	
	//check if this password is registered. if it is, we believe that it's them. if it's
	//not, they had better be a new server trying to register this password.
	ret.hash = serverPass(recvBuf);
	bool validPassword = 
			(dbClient.getCollection(serverCollection).count(["password_hash":Bson(ret.hash)]) > 0);
	
	//if we're expecting a specific hash, make sure that's the one that came out
	if(rightHash !is null && rightHash != ret.hash)
	{
		theSSL.write("I");
		ret.command = '!';
		return ret;
	}
	
	//read a single byte to see what sort of message this is.
	ubyte[] choiceBuf = new ubyte[1];
	theSSL.read(choiceBuf);
	ret.command = (cast(char[])choiceBuf)[0];
	
	//if they're registering, we say INvalid if the password IS already registered
	if(ret.command=='r' && validPassword || ret.command!='r' && ret.command!='A' && !validPassword)
	{
		theSSL.write("I");
		ret.command = '!';
	}
	else
		theSSL.write("K");
	
	//if it's an admin access attempt, verify the secret
	if(ret.command=='A')
	{
		//NOTE GIVEN HOW THE LOGIC IS SET UP, THIS NEXT LINE IS CRUCIAL TO KEEP UNAUTHORIZED PEOPLE OUT!
		ret.command='?';
		
		ubyte[128] secretBuf;
		theSSL.read(secretBuf);
		char[128] asChars = cast(char[128])secretBuf;
		
		if(asChars.indexOf("REDACTED")>=0)
			ret.command = 'A';
	}

	return ret;
}

