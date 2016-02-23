module group_logic;

import std.process;
import std.random;
import std.math;

import std.digest.sha;
import std.uuid;

import vibe.d;

import server;
import utility;

import client_db_logic;




//try to put this user into a group they aren't in yet, at the highest level available to them.
//create a new group if that's the right thing to do.
//return the password hash of a server in that group that the user can be given.
string tryJoinGroup(string userEmail, int atLevel)
{
	auto gCol = dbClient.getCollection(groupCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	auto uCol = dbClient.getCollection(clientCollection);
	
	ulong freeServers = sCol.count
	([
		"is_assigned": Bson(false), 
		"is_online": Bson(true)
	]);
	
	
	
	
	
	//find groups at this level with fewer users assigned than what we currently consider the max load
	auto results = gCol.find(["level": Bson(atLevel)]);
	
	double chinaSuspicionComp;
	double iranSuspicionComp;
	Bson userID;
	Bson[] thisUserBeenWith;
	//NOTE huh.... can't reuse a variable for the results of find i guess? weird.
	auto results2 = uCol.find(["email": Bson(userEmail)]);
	foreach(doc ; results2)
	{
		chinaSuspicionComp = to!double(doc["suspicion_complement_CN"]);
		iranSuspicionComp = to!double(doc["suspicion_complement_IR"]);
		userID = doc["_id"];
		if(!doc["users_been_with"].isNull())
			foreach(thingy ; doc["users_been_with"])
				thisUserBeenWith~=thingy;
		break;
	}
	
	Group[] allGroups;
	bool foundOne = false;
	foreach(doc ; results)
	{
		int minBandwidth = 999999999;
		bool canUseThisGroup = true;
		Group tempGrp;
		try{
		tempGrp.isAlive = to!bool(doc["is_alive"]);
		tempGrp.level = to!int(doc["level"]);
		}catch(Exception e){logInfo("FGDSFDS DFDDDDDDDD "~to!string(e));}
		
		if(!doc["users"].isNull())
			foreach(thingy ; doc["users"])
			{
				if(to!string(thingy) != to!string(userID))
					tempGrp.users ~= thingy;
				else
					canUseThisGroup = false;//shouldn't put the user into a group they're already in!
			}
		if(!doc["servers"].isNull())
			foreach(thingy ; doc["servers"])
			{
				string sHash = cast(string)extractVibeString(thingy);
				tempGrp.servers ~= sHash;
				
				auto lololres = sCol.find(["password_hash": Bson(sHash)]);
				foreach(ddoocc ; lololres)
					minBandwidth = to!int(ddoocc["offered_bandwidth"]) < minBandwidth ? 
								to!int(ddoocc["offered_bandwidth"]) : minBandwidth;
			}
		if(!doc["user_suspicions_CN"].isNull())
			foreach(thingy ; doc["user_suspicions_CN"])
				tempGrp.userSuspicionsCN ~= to!double(thingy);
		if(!doc["user_suspicions_IR"].isNull())
			foreach(thingy ; doc["user_suspicions_IR"])
				tempGrp.userSuspicionsIR ~= to!double(thingy);
		tempGrp.myID = doc["_id"];
		
		bool probablyWindows = to!bool(doc["probably_windows"]);
		if(probablyWindows && 
			tempGrp.users.length >=4 && 
			minBandwidth / 80 < tempGrp.users.length) //accomodate windows servers
			canUseThisGroup = false;
		
		if(canUseThisGroup)
		{
			foundOne = true;
			allGroups ~= tempGrp;
		}
	}
	
	if(!foundOne) //there are no groups we're willing to assign to! try to make a new one!
		//create the group (or fail = null) + add a server to it + add user to group / group to user
		return tryCreateGroup(userID, chinaSuspicionComp, iranSuspicionComp, atLevel);
	
	/+now, the suspicion diversity. put this user in the group where they will contribute most (or overlap least)
	to suspicion diversity for each country. alright to stay simple i think it makes most sense to just use
	variance. so, the logic is, see how variance is gained/lost by adding this value to the set.
	break ties by putting in lightest loaded group.+/
	//(NOTE: recall that this suspicion diversity thing is a much simpler approximation of n-ary search.)
	double[] varianceChanges;
	for(int i=0;i<allGroups.length;i++)
	{
		//compute the variance of the original CN and IR sets for group i
		double meanCN;
		double sum = 0;
		double varianceCN = 0;
		for(int j=0;j<allGroups[i].userSuspicionsCN.length;j++)
			sum+=allGroups[i].userSuspicionsCN[j];
		meanCN = sum / allGroups[i].userSuspicionsCN.length;
		for(int j=0;j<allGroups[i].userSuspicionsCN.length;j++)
			varianceCN+=(allGroups[i].userSuspicionsCN[j]-meanCN)*(allGroups[i].userSuspicionsCN[j]-meanCN);
		varianceCN /= (allGroups[i].userSuspicionsCN.length - 1);
		
		double meanIR;
		sum = 0;
		double varianceIR = 0;
		for(int j=0;j<allGroups[i].userSuspicionsIR.length;j++)
			sum+=allGroups[i].userSuspicionsIR[j];
		meanIR = sum / allGroups[i].userSuspicionsIR.length;
		for(int j=0;j<allGroups[i].userSuspicionsIR.length;j++)
			varianceIR+=(allGroups[i].userSuspicionsIR[j]-meanIR)*(allGroups[i].userSuspicionsIR[j]-meanIR);
		varianceIR /= (allGroups[i].userSuspicionsIR.length - 1);
		
		//now get the variance you would get if you added this value to the sets
		double[] testCN;
		double[] testIR;
		
		testCN ~= allGroups[i].userSuspicionsCN;
		testCN ~= chinaSuspicionComp;
		testIR ~= allGroups[i].userSuspicionsIR;
		testIR ~= iranSuspicionComp;
		
		double meanCN2;
		sum = 0;
		double varianceCN2 = 0;
		for(int j=0;j<testCN.length;j++)
			sum+=testCN[j];
		meanCN2 = sum / testCN.length;
		for(int j=0;j<testCN.length;j++)
			varianceCN2+=(testCN[j]-meanCN2)*(testCN[j]-meanCN2);
		varianceCN2 /= (testCN.length - 1);
		
		double meanIR2;
		sum = 0;
		double varianceIR2 = 0;
		for(int j=0;j<testIR.length;j++)
			sum+=testIR[j];
		meanIR2 = sum / testIR.length;
		for(int j=0;j<testIR.length;j++)
			varianceIR2+=(testIR[j]-meanIR2)*(testIR[j]-meanIR2);
		varianceIR2 /= (testIR.length - 1);
		
		//...record the computed variance change.
		varianceChanges ~= (varianceCN2-varianceCN) + (varianceIR2-varianceIR);
	}
	double bestVarianceChange = -999.9f;
	//find the best variance change value...
	for(int i=0;i<allGroups.length;i++)
		if(varianceChanges[i] > bestVarianceChange)
			bestVarianceChange = varianceChanges[i];
	
	//now find the best choice, resolving variance-change-ties by choosing group with fewest users
		//(TODO this should be lightest loaded, i.e. consider bandwidth too, not just number of users)
	int bestInd = 0;
	ulong fewestAssigned = 999999;
	for(int i=0;i<allGroups.length;i++)
		if(varianceChanges[i] + 0.005f > bestVarianceChange && allGroups[i].users.length < fewestAssigned)
		{
			bestInd = i;
			fewestAssigned = allGroups[i].users.length;
		}
		
	//phew ok allGroups[bestInd] is the group we have decided to join.

	//add the user to the chosen group...	
	gCol.update([
				"_id": allGroups[bestInd].myID
			],[
				"$addToSet": ["users": userID,
							"user_suspicions_CN": Bson(chinaSuspicionComp),
							"user_suspicions_IR": Bson(iranSuspicionComp),
			]]);
	//(and add group to the user's groups)
	uCol.update(["_id": userID],["$addToSet": ["current_groups": allGroups[bestInd].myID]]);
	
	//(and add this user to all group members' users_been_with, and add them to the newbie)
	foreach(member ; allGroups[bestInd].users)
		uCol.update(["_id": member],["$addToSet": ["users_been_with": userID]]);
	//add everyone else to the newbie
	uCol.update(["_id": userID],["$addToSet": ["users_been_with": [ "$each": allGroups[bestInd].users]]]);
	
	//...and pick the best server from that group, just like in needServer
	ulong minUsers = 9999999;
	string minServerHash = null;
	ulong curCount;
	foreach(candidate ; allGroups[bestInd].servers)
		if((curCount = uCol.count(["servers_given": ["$in": [candidate]]])) < minUsers)
		{
			minUsers = curCount;
			minServerHash = candidate;
		}
	return minServerHash;
}

//create a new group at this level, if there are any servers we can assign at this level.
//assign a single server to it, and return that server's password hash.
string tryCreateGroup(Bson userID, double userCompSusCN, double userCompSusIR, int atLevel)
{
	logError(niceCurTime()~": tryCreateGroup()...");
	scope(exit) logError(niceCurTime()~": tryCreateGroup() done.");
	
	string chosenServer = pickServerAtLevel(atLevel);
	if(chosenServer is null)
		return cast(string)null;
	
	auto sCol = dbClient.getCollection(serverCollection);
	auto uCol = dbClient.getCollection(clientCollection);
	auto gCol = dbClient.getCollection(groupCollection);
	
	Bson[] theServerArr = new Bson[1];
	theServerArr[0] = Bson(chosenServer);
	Bson[] userIDArr = new Bson[1];
	userIDArr[0] = userID;
	Bson[] suspCN = new Bson[1];
	Bson[] suspIR = new Bson[1];
	suspCN[0] = Bson(userCompSusCN);
	suspIR[0] = Bson(userCompSusIR);
	
	//create the group. add to the new group the user we're creating the group on behalf of.
	gCol.insert(Bson
	([
		"level": Bson(atLevel),
		"servers": Bson(theServerArr),
		"is_alive": Bson(true),
		"users": Bson(userIDArr),
		"user_suspicions_CN": Bson(suspCN),
		"user_suspicions_IR": Bson(suspIR)
	]));
	//is there an easy way to get _id from insert? i don't think so, so, lol...
	auto results = gCol.find(["servers": ["$in": [theServerArr[0]]]]);
	Bson lolID;
	foreach(doc ; results){lolID = doc["_id"];break;}
	logInfo(niceCurTime()~": created group "~to!string(lolID));
	
	//set this server's database entry to reflect that it's been assigned. (NOTE: as in other places where
	//we choose and return a server PH, we don't actually tell the server about this change right here, nor
	//do we put this server into the user's list.)
	sCol.update
	([
		"password_hash": Bson(chosenServer)
	],[
		"$set": [	"is_assigned": Bson(true),
				"group": lolID
	]]);
	
	//group entry has the user, so we should add the new group to the user's array of groups
	uCol.update(["_id": userID],["$addToSet": ["current_groups": lolID]]);
	
	return chosenServer;
}


//try to add a server from the unused server pool to this group. return the server chosen, or null if none.
string addSomeServerToGroup(Group group)
{
	string chosenServer = pickServerAtLevel(group.level);
	if(chosenServer is null)
		return cast(string)null;
	
	auto sCol = dbClient.getCollection(serverCollection);
	//set this server's database entry to reflect that it's been assigned. no further action necessary
	//right now; we only need to tell the server the login credentials, and we aren't doing that right now.
	sCol.update
	([
		"password_hash": Bson(chosenServer)
	],[
		"$set": [	"is_assigned": Bson(true),
				"group": group.myID,		
	]]);
	
	logInfo(niceCurTime()~": added server "~chosenServer[0..8]~" to group "~to!string(group.myID));
	
	return chosenServer;
}

SysTime lastComplainedAboutNoServers;
bool lastComplainedStartup = true;

//see if it's possible to assign a new server to a group of this level, but don't actually change anything.
//return null if it's impossible, otherwise pick a server and return its password hash.
string pickServerAtLevel(int level)
{
	if(lastComplainedStartup)
	{
		lastComplainedAboutNoServers = SysTime(Date(1970, 1, 1), UTC());
		lastComplainedStartup = false;
	}
	
	//sort all UP unassigned servers by uptime and bandwidth. divide at 0, 14.3, 28.6, ..., 85.7, 100th 
	//percentile; the group to be added to gets a server added from the appropriate percentile.
	
	//the sorting will be by uptime, unless bandwidth is less than 200, in which case weight them evenly.
	//more precisely, (uptime-24hrs)/24hrs + (bw_capped_at_200 - 200)/200.
	struct PHandScore
	{
		string ph;
		double score;
	}
	PHandScore[] allUnServers;
	
	MongoCollection sCol = dbClient.getCollection(serverCollection);
	auto results = sCol.find
	([
		"is_assigned": Bson(false), 
		"is_online": Bson(true)
	]);
	foreach(doc ; results)
	{
		PHandScore temp;
		temp.ph = extractVibeString(doc["password_hash"]);
		logInfo(temp.ph ~ " is a candidate for becoming a level "~to!string(level)~" server.");
		Duration uptime = 	(cast(BsonDate)doc["estimated_stop"]).toSysTime() -
						(cast(BsonDate)doc["estimated_start"]).toSysTime();
		temp.score = (uptime.total!"hours"() - 24.0f) / 24.0f; //NOTE .total!"hours"() returns a long
		int bandwidth = to!int(doc["offered_bandwidth"]);
		temp.score += ((bandwidth > 200 ? 200 : bandwidth) - 200.0f) / 200.0f;
		
		allUnServers ~= temp;
	}
		
	bool serverRank(PHandScore s1, PHandScore s2) {return s1.score < s2.score;}
	sort!(serverRank)(allUnServers);
	
	//none available! oh no!
	if(allUnServers.length == 0)
	{
		logInfo(niceCurTime()~": Completely out of servers!!! (HACK HACK TODO TIME OVERRIDE)");
		if(lastComplainedAboutNoServers + dur!"hours"(12) < Clock.currTime())
		{
			logInfo(niceCurTime()~": Completely out of servers!!!");
			lastComplainedAboutNoServers = Clock.currTime();
		}
		return cast(string)null;
	}
	//keep two in reserve for higher levels
	else if(level < 3 && allUnServers.length <= 2)
	{
		if(lastComplainedAboutNoServers + dur!"hours"(12) < Clock.currTime())
		{
			logInfo(niceCurTime()~": Nearly out of servers!!! Refused a low-level user.");
			lastComplainedAboutNoServers = Clock.currTime();
		}
		return cast(string)null;
	}
	//keep good ones in reserve for higher levels
	else if(level < 3 && allUnServers.length < 6 && allUnServers[2].score > -0.5f)
		return cast(string)null;
	
	//choose the appropriate percentile: 0th for level 0, 100th for level 7
	int chosenIndex = cast(int)round(0.14286f*level*allUnServers.length);
	if(chosenIndex >= allUnServers.length)
		chosenIndex = cast(int)allUnServers.length - 1;
	
	while(chosenIndex >= 0)
	{
		if(areYouStillThere(allUnServers[chosenIndex].ph))
			return allUnServers[chosenIndex].ph;
		else
			logInfo("when trying to assign "~allUnServers[chosenIndex].ph~" to a group, it was not still there.");
		chosenIndex--;
	}
	return cast(string)null;
}


//marks group as blocked in this country (and therefore archived)
//demotes everyone in the group who has seen ANY of group.blockedServers
void demoteGroupOf(Group group, string country)
{
	auto uCol = dbClient.getCollection(clientCollection);
	auto gCol = dbClient.getCollection(groupCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	Bson[] badUsers;
	
	logError(niceCurTime()~": demoteGroupOf("~to!string(group.myID)~")...");
	scope(exit) logError(niceCurTime()~": demoteGroupOf("~to!string(group.myID)~") done.");
	
	foreach(user ; group.users)
	{
		//get their servers_given field
		auto results = uCol.find(["_id": user]);
		string[] myServers;
		bool foundOne = false;
		foreach(doc ; results)
		{
			foundOne = true;
			if(!doc["servers_given"].isNull())
				foreach(thingy ; doc["servers_given"])
					myServers ~= extractVibeString(thingy);
			break;//should only be one
		}
		if(!foundOne)
			continue;
		
		//if any of their servers is found in group.blockedServers, queue them to be demoted
		OuterLoop: foreach(s1 ; myServers)
			foreach(s2 ; group.blockedServers)
				if(s1 == s1)
				{
					badUsers ~= user;
					break OuterLoop;
				}
	}
	
	//check for divide by 0 juuuuust in case... 
	if(badUsers.length == 0)
	{
		logError("WARNING! Bailing out of demoteGroupOf to prevent division by zero.");
		return;
	}
	
	//calculate suspicion to add: n bad users = 1/n chance of being the culprit (so 1-1/n for complement)
	double addSuspicionComplement = 1.0f - 1.0f / cast(double)badUsers.length;
	
	//for each bad user: trust--, and add to country-suspicion
	//NOTE NOTE NOTE NOTE if add new countries, remember to change this
	string whichSusp = (to!string(country).toUpper == "IR" ?
							"suspicion_complement_IR" : "suspicion_complement_CN");
	foreach(user ; badUsers)
	{
		uCol.update
		([
			"_id": user
		],[
			"$inc": ["trust": Bson(-1)],
			"$mul": [whichSusp: Bson(addSuspicionComplement)]
		]);
		
		auto badResults = uCol.find(["_id": user]);
		foreach(doc ; badResults)
		{
			double susCompIR = to!double(doc["suspicion_complement_IR"]);
			double susCompCN = to!double(doc["suspicion_complement_CN"]);
			int trust = to!int(doc["trust"]);
			if(trust <= -NEG_MAX  || susCompIR  < 0.66666 || susCompCN < 0.66666)
			{
				uCol.update
				([
					"_id": user
				],[
					"$set": ["banned": Bson(true)]
				]);
			}
		}
	}
	
	//mark group as archived, and blocked in country
	gCol.update
	([
		"_id": group.myID
	],[
		"$addToSet": ["blocked_in": Bson(country)],
		"$set": ["is_alive": Bson(false)]
	]);
	
	//mark each server as blocked in country
	foreach(s ; group.blockedServers)
		sCol.update(["password_hash": s],
				  ["$addToSet": ["blocked_in": Bson(country)]]);
}

