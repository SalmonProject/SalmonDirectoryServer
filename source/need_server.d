module need_server;

import std.process;
import std.random;
import std.math;

import std.digest.sha;
import std.uuid;

import vibe.d;

import server;
import utility;

import client_db_logic;
import group_logic;

string generateNeedServerResponse(string theIP, string psk, int offeredBW, string theCert)
{
	return theIP~" "~psk~" "~to!string(offeredBW)~"\n"~theCert;
}

string stringFromRandomVPNGateItem(int chosenNumber)
{
	string retStr = null;
	
	auto vCol = dbClient.getCollection("salmonalpha.vpngate");
	auto res = vCol.find(["number": Bson(chosenNumber), "known_good": Bson(true)]);
	foreach(doc ; res)
	{
		retStr = "VPNGATE";
		string ipAddr = extractVibeString(doc["ipaddr"]);
		string theCert = extractVibeString(doc["server_cert"]);
		int port = to!int(doc["port"]);
		int offeredBW = to!int(doc["offered_bandwidth"]);
		
		retStr ~= ipAddr~":"~to!string(port)~" vpn"~" "~to!string(offeredBW)~" "~theCert~"\n";
		
		break;
	}
	
	return retStr;
	
	//return "VPNGATE" ~ "1.2.3.4" ~ ":" ~ "443" ~ " " ~ 
	//		"vpn" ~ " " ~ 
	//		"1234" ~ " " ~ 
	//		"BEGINCERTdfgsdfgENDCERT" ~ "\n";
/*	
return "VPNGATE107.150.42.28:443 vpn 1686 "~
"-----BEGIN CERTIFICATE-----*MIIDFjCCAf6gAwIBAgIFAJNDd2cwDQYJKoZIhvcNAQELBQAwQjEYMBYGA1UEAwwP*aDVoNW42bDVyaXcubmV0MRkwFwYDVQQKDBB3M2w0N2EgMGkzMGNudjFzMQswCQYD*VQQGEwJVUzAeFw0xNTA1MTUxNzQ5MDhaFw0yMDA3MjUxNzQ5MDhaMEIxGDAWBgNV*BAMMD2g1aDVuNmw1cml3Lm5ldDEZMBcGA1UECgwQdzNsNDdhIDBpMzBjbnYxczEL*MAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdlecU*HP8Qhsx+olFSdt/jO72j5HgTuMi9Pp5e7PoqQoYZ2kxOoh1/YIPl3GM05V6zPyPO*BucpXWpd8nug5xvxiQ0pb5Gt/4tvOWahN+HX2kWHv77vnpsI59ypPI0a3PAuGsAB*zTHb9hpb76/II5auhhch6OrHM2xiIYHdqJQK3mUNMQHlJGdYzc1qcym4qmZzSEti*+ty3rNhkMHGGyRWe1vWtv8YfWMefLYLCTDHZuI9eCb2bA21WSRqtsJ3Bb2opbCke*L8Q/QdFLNqemwJngikJOBZvdSj7ROyUAAmj8vKhNtrDGOzqdi5BdBTlROEA1tH4q*lZUMP+wSbftqqB01AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN*AQELBQADggEBAGyRGsaHLMuRdYP1dtStuXVEOiA7gkRjh5URnZ8mZH+g7Z8aniBT*XjWQuzu3dRxTDUk4f1yN6gBqVkYd+yf2v+/gD2QlmRFKgga1bx6ZoNkxb+TLnVc/"~"*"~
"/jOobTMjH+aycHRppsZLGDBot87X3gjdhzYvSg9OVXi165x5v22D35aV+Kh06G0q*h7fwMgAQe62vbxWo+g5Dh2+rREnNe+qzBxVfh9AvLLtK7VM7d3EaAPiyrSea/xyc*T7XCrOQdGhPjBHazAW2dFFGOYgsiNmc09NtCbL3Cbj7Pj/7z1FBWL7O0zTq/iJgl*nPrU4smB2IkK31WLT570xwYqEWgaOGZ9kSo=*-----END CERTIFICATE-----\n";
*/
}

struct VPNGateServer
{
	string ipaddr;
	int port;
	string theCert;
	int offeredBW;
}



//db.v.count({"offered_bandwidth": {"$gt": 1500}, "known_good": true})
string noSalmonButVPNGateServers()
{
	string retStr = "$18\n";
	
	//auto vCol = dbClient.getCollection("salmonalpha.vpngate");
	//int countVPNG = to!int(vCol.count(["number": ["$gte": 1]]));
	
	auto vCol = dbClient.getCollection("v.v");
	auto res = vCol.find(["known_good": Bson(true), "offered_bandwidth": Bson(["$gt": Bson(4000)])]);
	
	VPNGateServer[] goodServers;
	foreach(doc ; res)
	{
		VPNGateServer tempS;
		tempS.ipaddr = extractVibeString(doc["ipaddr"]);
		tempS.theCert = extractVibeString(doc["server_cert"]);
		tempS.port = to!int(doc["port"]);
		tempS.offeredBW = to!int(doc["offered_bandwidth"]);
		
		goodServers ~= tempS;
	}
	
	int[] randomPerm = knuthShuffle(cast(int)goodServers.length);
	
	int numFound=0;
	for(int i=0; i<randomPerm.length && numFound < 16 ;i++)
	{
		VPNGateServer tempS = goodServers[randomPerm[i]-1];
		retStr ~= "VPNGATE"~tempS.ipaddr~":"~to!string(tempS.port)~" vpn"~" "~to!string(tempS.offeredBW)~
		" "~tempS.theCert~"\n";
		
		numFound++;
	}
	//logError("VPN Gate: \n\n"~retStr);
	return retStr;
}

string notKnownGoodVPNGate(int serversToReturn)
{
	string retStr = "$18\n";
	auto vCol = dbClient.getCollection("salmonalpha.vpngate");
	
	int curTestLimit = 0;
	int serversFound = 0;
	while(serversFound < serversToReturn)
	{
		foreach(doc ; vCol.find(["known_good": Bson(false), "tests": Bson(curTestLimit)]))
		{
			string ipAddr = extractVibeString(doc["ipaddr"]);
			string theCert = extractVibeString(doc["server_cert"]);
			int port = to!int(doc["port"]);
			int offeredBW = to!int(doc["offered_bandwidth"]);
			
			retStr ~= "VPNGATE"~ipAddr~":"~to!string(port)~" vpn"~" "~to!string(offeredBW)~" "~theCert~"\n";
			
			serversFound++;
			if(serversFound >= serversToReturn)
				break;
		}
		curTestLimit++;
		if(curTestLimit == 4)
			break;
	}
	return retStr;
}

//oh boy! the place where all the cool logic happens. either all of their servers are offline,
//in which case we just assign a new server to their group, OR their server was blocked,
//in which case the fun logic happens.
//NOTE RETURN FORMAT IS NOW "ipaddr psk offeredbw\nSERVERCERT---sdfDFSGSDF" [see function right above]
string needServer(string email, string[] IPaddrsReportedOffline, string[] IPaddrsReportedError)
{
	logError(niceCurTime()~": "~email~" needServer()...");
	scope(exit) logError(niceCurTime()~": "~email~" needServer() done.");
	
	//get all of client's groups, and client's other info
	Group[] allGroups;
	Group[] groupsToDemote;
	string userCountry;
	string userPassword;
	string recmndnParent;
	double suspicionComplementCN;
	double suspicionComplementIR;
	int trust;
	bool isBanned;
	string[] curServPHs;
	string[] curServIPs;
	
	auto uCol = dbClient.getCollection(clientCollection);
	auto gCol = dbClient.getCollection(groupCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	auto results = uCol.find(["email": Bson(email)]);
	bool emailIsRegisteredUser = false;
	foreach(doc ; results)
	{
		emailIsRegisteredUser = true;
		isBanned = to!bool(doc["banned"]);
		userCountry = extractVibeString(doc["nationality"]);
		userPassword = extractVibeString(doc["vpn_password"]);
		recmndnParent = extractVibeString(doc["my_recommender"]);
		suspicionComplementCN = to!double(doc["suspicion_complement_CN"]);
		suspicionComplementIR = to!double(doc["suspicion_complement_IR"]);
		trust = to!int(doc["trust"]);
		

		
		//HACK-ish: while we still have few servers, LOW LVEL PEOPLE ALWAYS GET VPN GATE SERVERS!
		if(trust <= 0)
		{
			logInfo(niceCurTime()~": needServer(): "~email~" will receive a VPNGate server (happened early in the code because trust was "~to!string(trust)~" (lteq 0).");
			return noSalmonButVPNGateServers();
		}
		
		
			
		/++they are reporting which servers they actually tried, so we should first see if we 
		think we assigned any servers that they haven't yet learned about (according to the
		list they said they tried). if so, we can just return that IP - without all the fancy 
		pleaseAddCredentials() stuff.+/
		
		if(!doc["servers_given"].isNull())
			foreach(thingy ; doc["servers_given"])
				curServPHs ~= extractVibeString(thingy);
		
		foreach(ph ; curServPHs)
			foreach(Sdoc ; sCol.find(["password_hash": Bson(ph)]))
			{
				if(!(Sdoc["current_ip"].isNull() || Sdoc["offered_bandwidth"].isNull() ||
					Sdoc["server_cert"].isNull()))
				{
					string curServIP = extractVibeString(Sdoc["current_ip"]);
					curServIPs ~= curServIP;
					
					bool didTryThisIP = false;
					foreach(triedIP ; IPaddrsReportedOffline)
						if(curServIP == triedIP)
							didTryThisIP = true;
						
					foreach(triedIP ; IPaddrsReportedError)
						if(curServIP == triedIP)
							didTryThisIP = true;
					
					if(!didTryThisIP)
						return pleaseAddCredentials(cast(string)ph, email);
				}
				break;
			}
		
		
		
		
		
		
		//ANOTHER HACK: HIGH PEOPLE ALWAYS GET REAL SERVERS!
		if(trust >= 7)
		{
			string newGroupServer = tryJoinGroup(email, trust);
			//if they weren't able to get into a group, they're stuck.
			if(newGroupServer is null)
			{
				//actually, let's use the more friendly (and more helpful to us) "not enough servers; please recruit your friends" one.
				logInfo(niceCurTime()~": needServer() HACK: "~email~" will receive a VPNGate server.");
				return noSalmonButVPNGateServers();
				
				//they are (temporarily) shut out of the system!
				//return "$19";//"$Sorry, there are currently no servers you can access. You may have come under suspicion if many of the servers you were given got blocked. Wait a few days and try again.";
			}
			logInfo(niceCurTime()~": needServer() HACK: "~email~" was added to a group, and received server "~newGroupServer[0..8]~" from that group.");
			
			//give the added server to the user
			uCol.update
			(["email": Bson(email)
			],["$addToSet": ["servers_given": Bson(newGroupServer)]]);
			return pleaseAddCredentials(newGroupServer, email);
		}
		
		
		
		
		
		
		
		//NOTE NOTE i think how things are shaking out, the banning should never happen here,
		//but let's keep the trust/suspicion checks just in case. ban() is idemponent, so it's fine.
		if(isBanned || trust <= -NEG_MAX )//TODO TODO TODO TODO  || suspicion is too high!! TODO TODO
		{
			logInfo("BANNING THIS GUY: "~email);
			ban(email);
			return "$11";//"$Your account is permanently banned. If you aren't helping a government block servers, then we're sorry. Unfortunately, unless we had many more VPN servers to burn through, it's impossible to be 100% accurate with our bans. If you want to get a new account, get a recommendation code from a highly trusted user.";
		}
		
		Bson[] groupBsonArray;
		if(!doc["current_groups"].isNull())
			foreach(thingy ; doc["current_groups"])
				groupBsonArray ~= thingy;
			
		foreach(grp ; groupBsonArray)
		{
			auto results2 = gCol.find(["_id": grp]);
			foreach(doc2 ; results2)
			{
				Group tempGrp;
				tempGrp.isAlive = to!bool(doc2["is_alive"]);
				tempGrp.level = to!int(doc2["level"]);

				if(!doc2["users"].isNull())
					foreach(thingy ; doc2["users"])
						tempGrp.users ~= thingy;
				if(!doc2["servers"].isNull())
					foreach(thingy ; doc2["servers"])
						tempGrp.servers ~= extractVibeString(thingy);
				if(!doc2["user_suspicions_CN"].isNull())
					foreach(thingy ; doc2["user_suspicions_CN"])
						tempGrp.userSuspicionsCN ~= to!double(thingy);
				if(!doc2["user_suspicions_IR"].isNull())
					foreach(thingy ; doc2["user_suspicions_IR"])
						tempGrp.userSuspicionsIR ~= to!double(thingy);
				tempGrp.myID = doc2["_id"];
				allGroups ~= tempGrp;
				break; //there should only be 1, so whatever
			}
		}
		break; //there should only be 1, so whatever
	}
	
	if(!emailIsRegisteredUser)
	{
		logInfo(niceCurTime()~": "~email~" is not a registered user!");
		return "$6"; //We don't have a record of you having started the reg process. (close enough!)
	}
	
	logError(niceCurTime()~": needServer() finished extracting info about "~email~"...");

	/++             DESCRIPTION OF LOGIC AS IMPLEMENTED
	========================================================================
	(first, some notation: does a demoted group get destroyed? no. rather, we say "hey this group 
	was blocked in this country", which marks the group as "archived" (as opposed to "alive"), 
	but we let the group continue existing.	 (archived = NEVER add new servers to it) 
	
	ok, the logic. sort the user's groups in descending trust order.
	for each group:
		if the group is alive AND has no up servers AND we haven't picked a group to add to yet
			mark this as the group to add a server to (if we do end up wanting to do that)
		if the group is archived AND has servers up AND we haven't picked a server to return yet
			choose the best unblocked server in the group as the one to return
		if the group is alive AND has servers up
			if any of its servers are blocked
				put it on a queue of groups to be archived+demoted
			else if (none of its servers are blocked) AND we haven't picked a server to return yet
				choose the best server in the group as the one to return
	NOTE in this stage we are just making notes on what to do; none of those actions above,
	such as adding a server or returning a server, actually happen during this loop.
	
	once that loop is done, first demote any groups we decided to demote. then, try to help the user:
	first, tell them about a good server in a group they're already in, if possible. else, add a server
	to one of their groups, if that's ok. if neither of those options are ok, try to put them in a new group.
	========================================================================+/
	
	//sort by descending trust level
	bool groupComp(Group g1, Group g2) {return g1.level > g2.level;}
	sort!(groupComp)(allGroups);
	
	//we add at most one server to a group. since we go by descending trust level, we first
	//try adding to the highest level group eligible to be added to.
	int[] addServerToGroupIndices;
	//give at most one new server to client. we go by descending level => get the highest level server possible.
	string giveServer = null;
	//if giveServer has a value, that takes precedence over addServerToGroupIndex.
	
	/+TODO TODO TODO TODO this would let us do it in parallel... definitely desirable
	string[allGroups.length][] allGroupsServers;
	string[allGroups.length][] allGroupsServersUp;
	for(int i=0;i<allGroups.length;i++)
		allGroupsServers[i] = allGroups[i].servers;
	allGroupsServersUp = areYallStillThere(allGroupsServers);
		+/
	
	for(int i=0;i<allGroups.length;i++)
	{
		string[] serversUp;
		/+TODO TODO
		serversUp = allGroupsServersUp[i];
		+/
		//TODO TODO this should be in parallel over ALL groups, i.e., pull this out of the for loop...
		foreach(sph; allGroups[i].servers)
			if(areYouStillThere(sph))
			{
				serversUp ~= sph;
				logError(niceCurTime()~": needServer("~email~"): server "~sph[0..8]~" WAS still there.");
			}
			else
				logError(niceCurTime()~": needServer("~email~"): server "~sph[0..8]~" was NOT still there.");
		
		//yup, none in this group is up, but it is possible to assign new servers to it
		if(serversUp.length == 0 && allGroups[i].isAlive)
		{
			logError(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~" has no servers up, but is alive: we will add a server to it.");
			//so long as we don't later see any blocked or up servers, add a server to this group
			addServerToGroupIndices ~= i;
		}
		else if(serversUp.length > 0 && !allGroups[i].isAlive)
		{
			logError(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~" has some servers up, but is NOT alive.");
			
			BlockCheckQuery[] theQueries = [];
			foreach(ph ; serversUp)
			{
				BlockCheckQuery curQuery;
				curQuery.serverPass = ph;
				curQuery.clientReportedError = false;
				
				for(int j=0; j<curServIPs.length && j<curServPHs.length; j++)
					if(curServPHs[j] == ph)
						for(int k=0; k<IPaddrsReportedError.length; k++)
							if(curServIPs[j] == IPaddrsReportedError[k])
								curQuery.clientReportedError = true;
			}
			RequestBlockCheckAllResult theCheckRes = requestBlockCheckAll(theQueries, email, 
															  userPassword, userCountry);
			if(theCheckRes.overrideResponse !is null)
			{
				logError(niceCurTime()~": needServer("~email~"): returning an overridden response from the (some servers are up and group is NOT alive) logic.");
				return theCheckRes.overrideResponse;
			}
			if(theCheckRes.unblocked.length > 0 && giveServer is null)
			{
				/+NOTE: the logic used here is "choose the one with fewest users currently assigned".
				this isn't necessarily the best way to do it - maybe consider (bandwidth/#users).+/
				ulong minUsers = 9999999;
				string minServerHash = null;
				ulong curCount;
				foreach(candidate ; theCheckRes.unblocked)
				{
					//NOTE this next line with the $in has been tested and works.
					try{curCount = uCol.count(["servers_given": ["$in": [candidate]]]);}
					catch(Exception e){logInfo("yup");curCount=0;}
					if(curCount < minUsers)
					{
						minUsers = curCount;
						minServerHash = candidate;
					}
				}
				giveServer = minServerHash;
			}
		}
		//servers are up and the group is alive
		else if(serversUp.length > 0 && allGroups[i].isAlive)
		{
			logError(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~" has some servers up, and IS alive.");
			
			//every server that we determined is online needs to be block-checked. the block check
			//function needs to know whether each server was reported erroneous (HTTPS GET succeeded)
			//by the client. so, for each server, figure that out, package the answer together with
			//the server's hash, and stick it onto the list of servers to be block checked.
			BlockCheckQuery[] theQueries = [];
			foreach(ph ; serversUp)
			{
				BlockCheckQuery curQuery;
				curQuery.serverPass = ph;
				curQuery.clientReportedError = false;
				
				for(int j=0; j<curServIPs.length && j<curServPHs.length; j++)
					if(curServPHs[j] == ph)
						for(int k=0; k<IPaddrsReportedError.length; k++)
						{
							if(curServIPs[j] == IPaddrsReportedError[k])
								curQuery.clientReportedError = true;
							else
								logError(niceCurTime()~": needServer("~email~"): WHOA WHOA curServIPs[j]: "~curServIPs[j]~" does not match IPaddrsReportedError[k]: "~IPaddrsReportedError[k]);
						}
						if(IPaddrsReportedError.length == 0)
							logError(niceCurTime()~": needServer("~email~"): wait....no error servers? I'm confused.");
						
				theQueries ~= curQuery;
			}
			RequestBlockCheckAllResult theCheckRes = requestBlockCheckAll(theQueries, email, 
															  userPassword, userCountry);
			if(theCheckRes.overrideResponse !is null)
			{
				logError(niceCurTime()~": needServer("~email~"): returning an overridden response from the (some servers are up and group IS alive) logic.");
				return theCheckRes.overrideResponse;
			}
			/+if [ALL] servers seem unblocked, tell the client about [ONE]. this
			is how members who later come ask for a server when we already added a server
			(due to all others just being down) get their servers. (also how they learn that a 
			server has switched to a new IP address.) +/
			if(theCheckRes.unblocked.length + theCheckRes.down.length == serversUp.length && 
				theCheckRes.unblocked.length > 0)//no servers are blocked, some are up; group is healthy
			{
				//return ONE of these to client. see NOTE above about logic.
				if(cast(string)giveServer is null)
				{
					ulong minUsers = 9999999;
					string minServerHash = null;
					ulong curCount;
					foreach(candidate ; theCheckRes.unblocked)
					{
						try{curCount = uCol.count(["servers_given": ["$in": [candidate]]]);}
						catch(Exception e){logInfo("again, yup");curCount=0;}
						if(curCount < minUsers)
						{
							minUsers = curCount;
							minServerHash = candidate;
						}
					}
					giveServer = minServerHash;
				}
			}
			//all the servers we thought were up were actually down
			else if(theCheckRes.down.length == serversUp.length)
			{
				logError(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~": all servers we thought up were actually down. Add a new server.");
				//well, turns out we should ACTUALLY be doing the 
				//"none in this group is up, but it is possible to assign new servers to it"
				//logic from above!!! fortunately, that is just a single line:
				
				//so long as we don't later see any blocked or up servers, add a server to this group
				addServerToGroupIndices ~= i;
			}
			else//there is at least one server that appears to be truly blocked.
			{
				logError(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~": at least one server appears blocked; group marked for demotion.");
				logInfo(niceCurTime()~": needServer("~email~"): group "~to!string(allGroups[i].myID)~": at least one server appears blocked; group marked for demotion.");
				//mark group for demotion. first make a note in its struct of which servers were blocked.
				foreach(up ; serversUp)
				{
					bool isBlocked = true;
					foreach(unb ; theCheckRes.unblocked)
						if(up == unb)
							isBlocked = false;

					if(isBlocked)
						allGroups[i].blockedServers ~= up;
				}
				groupsToDemote ~= allGroups[i];
			}
		}
		//else if no servers up and not alive: skip it; there is nothing to be done
	}
	/+--------------------------------------------------------------------------------
	OK! now we've examined every group. we know which groups to demote, and whether to
	tell the user about a new server, add a server to a group, or add user to a group.
	--------------------------------------------------------------------------------+/
	logError(niceCurTime()~": needServer("~email~"): Servers have been examined. Now demoting and/or adding servers and/or adding user to a group.");
	
	//first, demote and archive any alive group we saw a blocked server in
	foreach(group ; groupsToDemote)
		demoteGroupOf(group, userCountry);
	
	//now, decide how to help the user:
	//#1) if one of its groups had a good looking server [it hadn't heard about?], give it that. 
	if(giveServer !is null)
	{
		logInfo(niceCurTime()~": needServer(): "~email~" will receive server "~giveServer[0..8]);
		//add user to giveServer. first add giveServer to the user's list of servers...
		uCol.update
		([
			"email": Bson(email)
		],[
			//NOTE $addToSet has been tested and works.
			"$addToSet": ["servers_given": Bson(giveServer)
		]]);
		
		//...and then tell the server to accept their login credentials.
		return pleaseAddCredentials(giveServer, email);
	}
	//#2) else if we're willing to add a server to one of the user's groups, do it
	else if(addServerToGroupIndices.length > 0)
	{
		//try adding a server to every group we might want to add to in descending order
		string serverAdded = null; 
		for(int i=0; i < addServerToGroupIndices.length && serverAdded is null; i++)
			serverAdded = addSomeServerToGroup(allGroups[addServerToGroupIndices[i]]);
		
		if(serverAdded is null)
		{
			logInfo(niceCurTime()~": needServer(): "~email~" will receive a VPNGate server.");
			return noSalmonButVPNGateServers();
			//"$Salmon has run out of new servers at your trust level! We are unable to give you a new server until we get more volunteers. If you have friends in uncensored countries, please encourage them to volunteer. Some of your currently assigned servers might just be temporarily offline - try connecting again later.";
		}
		
		logInfo(niceCurTime()~": needServer(): "~email~" will have server "~serverAdded[0..8]~" added to their current group.");
		
		//give the added server to the user
		uCol.update
		(["email": Bson(email)
		],["$addToSet": ["servers_given": Bson(serverAdded)]]);
		return pleaseAddCredentials(serverAdded, email);
	}
	//#3) else try to add the user to a new group (possibly create a new group, even).
	else
	{
		string newGroupServer = tryJoinGroup(email, trust);
		//if they weren't able to get into a group, they're stuck.
		if(newGroupServer is null)
		{
			//actually, let's use the more friendly (and more helpful to us) "not enough servers; please recruit your friends" one.
			logInfo(niceCurTime()~": needServer(): "~email~" will receive a VPNGate server.");
			return noSalmonButVPNGateServers();
			
			//they are (temporarily) shut out of the system!
			//return "$19";//"$Sorry, there are currently no servers you can access. You may have come under suspicion if many of the servers you were given got blocked. Wait a few days and try again.";
		}
		logInfo(niceCurTime()~": needServer(): "~email~" was added to a group, and received server "~newGroupServer[0..8]~" from that group.");
		
		//give the added server to the user
		uCol.update
		(["email": Bson(email)
		],["$addToSet": ["servers_given": Bson(newGroupServer)]]);
		return pleaseAddCredentials(newGroupServer, email);
	}
	/+TODO TODO if the returned server seems down to them, the client program should give the option 
	"if you're sure you can't access any of these, you can click 'force retrieve new server'
	to get a new VPN server, in exchange for losing a little trust"+/
}

/+NOTE we definitely do NOT need "china trust, iran trust, etc". we should have separate suspicion, though.
hmmmmm... ok since i was getting a little worried that it might get out of hand, i think i'll allow
myself a stupid little hack. let's have the different suspicions just be china_suspicion iran_suspicion etc
for each country we're currently interested in. i believe it should be possible to add more later; 
you just treat nonexistant fields as 0. maybe have some logic so that the first time we see blocks 
coming from a country that doesn't have its own suspicion entry yet, the directory server sends me an 
email about it.+/

