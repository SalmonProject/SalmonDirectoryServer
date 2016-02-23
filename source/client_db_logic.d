module client_db_logic;

import std.process;
import std.random;
import std.math;

import std.digest.sha;
import std.uuid;

import vibe.d;

import server;
import utility;
//import stringtypes;

//the trust level defined as "high" (can start recommending)
const int HIGH_TRUST = 6;
//this is basically an "infinity" value
const int MAX_TRUST = 7;
//what level do you get when a MAX trust user recommends you?
const int TRUST_FROM_MAX_REC = HIGH_TRUST;
//similar
const int TRUST_FROM_HIGH_REC = 5;
//what's the highest daily usage score a server can report for a client?
const int MAX_DAILY_SCORE = 100;

const string SOCNETHOST = "REDACTED";

const int NEG_MAX = 4;
//when you're at level [index+NEG_MAX], what score do you need to reach to get promoted?
const int[] scoreNeededShifted = [1999999999, 90, 110, 150, 250, 350, 600, 1100, 1700, 3000, 1999999999, 1999999999];

//if we have enough servers, don't let a level [index+NEG_MAX] group get more than this many users from one country
const int[] maxTrustGroup = [0, 1, 2, 4, 8, 16, 24, 32, 40, 48, 100, 200];


//NOTE NOTE ok... i had wanted to move this into mongo, so that the server could be restarted at
//			any time without messing any state up, but now i'm remembering that we wanted to be
//			able to say "we don't store your osn stuff anywhere", so we shouldn't let mongo do it.
//			although, if we had a second mongo going, that was running in a ramdisk...
//
//			ANYWAYS, for now, just be sure to remember to be careful about restarting once we
//			have real users. OR, have an export/import function through the admin console.
struct JoiningUser
{
	bool osn_isRenren;
	char[] osn_id;
	char[] osn_post;
	char[] nationality; //this could be an enum, but we're just copying it right into mongo anyways
}
JoiningUser[string] joining; //the string index is the joiner's email


/+
messages the client might send to the directory server:
=======================================================
"begin registration": a new client trying to register an account with us. this should include:
-a social network url
-a post they haven't yet made on that social network account
This will put the client into the registration process. The directory server should go check
the social network account to be sure the post isn't there, and then respond to this message
with an "ok go ahead and post" message. (If the account was already used in our system, or their
proposed message is already up, we tell them about it.)
-------------------------------------------------------------------------------------------------------
"finish registration": a request from a client in the registration process, asking us
to check their OSN account for the post they said they would post
---------------------------------------------------------------------------------------------------
"recommended registration": a single step registration that doesn't use an OSN, instead just a rec code.
------------------------------------------------------------------------------------------------------
"recommend": this user wants to recommend someone. if it's ok for them to recommend, we generate
a random recommendation code, store it, and give it to them, which they can share with their friend.
-------------------------------------------------------------------------------------------------------
"redeem recommendation": this user registered without a recommendation, and now wants to get the trust boost
that a recommendation provides. they've sent us a registration code. if it's a good one, we boost their trust;
otherwise we say what went wrong.
---------------------------------------------------------------------------------------------------------
"need server": the client needs a server. either it's their first time connecting, or the servers they have
previously been given are all blocked and/or offline. we either return one or say "sorry, no."
if they're being given a new server, this function also takes care of instructing that server to accept the client.
+/


string socialNetworkCheck(string theID, string post, bool isRenren)
{
	logError(niceCurTime()~": socialNetworkCheck("~theID~") called...");
	string theURL;
	if(isRenren)
		theURL = "http://www.renren.com/"~theID~"/profile";
	else
		theURL = "https://www.facebook.com/"~theID;
	
	
	//sanitize
	theURL = translate(theURL, ['z':'z'], ['`', '"', '\\', '(', ')', '|', '$', '#', '*', ';', '\'', '<', '>', '\n', ' ']);
	post = translate(post, ['z':'z'],
					  ['`', '"', '\\', '(', ')', '|', '$', '#', '&', '*', ';', '\'', '<', '>', '\n', ' ', '?', ':']);
	
	string callString2 = "ssh -i /home/fred/.ssh/socnet_rsa REDACTED@"~SOCNETHOST~" ";
	callString2~= "\"F:/socnet_check.exe "~theURL~" \\\""~post~"\\\"\"";
	
	ProcessPipes pipes = pipeShell(callString2, Redirect.stdout);
	//NOTE yes we can keep this here, with the scope guard, because scope(exit) refers
	//to "when we exit the current scope"! pretty nifty, hooray for D.
	scope(exit) wait(pipes.pid);
	
	string outBuf = pipes.stdout.readln();
	pipes.stdout.close();
	
	if(outBuf.chomp()=="YES")
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): YES");
		return "YES";
	}
	else if(outBuf.chomp()=="NO")
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): NO");
		return "NO";
	}
	else if(outBuf.chomp()=="LOOKSFAKE")
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): LOOKSFAKE");
		return "LOOKSFAKE";
	}
	else if(outBuf.chomp()=="ERROR:PRIVATE")
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): ERROR:PRIVATE");
		return "ERROR:PRIVATE";
	}
	else if(outBuf.chomp()=="ERROR:TIMELINE")
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): ERROR:TIMELINE");
		return "ERROR:TIMELINE";
	}
	else
	{
		logError(niceCurTime()~": socialNetworkCheck("~theID~"): ERROR");
		return "ERROR";
	}
}

//NOTE for all of these functions, the returned string is exactly what should go in our emailed response.
string beginRegistration(string email, string socNetID, string post, string nationality, bool isRenren)
{
	auto uCol = dbClient.getCollection(clientCollection);
	
	logError(niceCurTime()~": "~email~" beginRegistration()...");
	scope(exit) logError(niceCurTime()~": "~email~" beginRegistration() done.");
	
	//we want to let them start the process even if the email is already half-joined.
	//the response email to their first beginReg attempt might not have gotten through,
	//and if we said "sorry, this email is already joined/joining" to a future beginReg,
	//then we actually make it impossible for that email address to ever be registered.
	if(uCol.count(["email": Bson(email)]) > 0)
		return "$1";//"$Error! This email address is already registered.";
	
	//NOTE this is a base64 encoded ubyte[], because vibe and/or mongo is being difficult
	string urlHash = secureHash(socNetID, isRenren);

	if(uCol.count(["osn_id_hash": Bson(urlHash)]) > 0)
		return "$4";//"couldn't access your social network account, ensure it's public"
				//(this is a lie, but actually it fits alright: if the government is trying to find
				//out if someone is using salmon, they may very well be keeping their profile private)
				//(was previously telling them $2 the account has been used to register; lol insecure)
	
	/+NOTE: must NOT use the following logic, or you can prevent someone else from
			using their own social network id to make an account! 
	foreach(joiner ; joining)
		if(joiner.osn_id == socNetID)
			return "$2";//"$Error! This social network account has already been used to create a Salmon account.";
	+/

	//NOTE need to prevent them from using various aliases, or links to facebook...
	//NOTE ok we have it worked out! they have to give the ID, not just entire url, and we construct the url.
	
	string postIsThere = socialNetworkCheck(socNetID, post, isRenren);
	if(postIsThere == "YES")
		return "$3";//"$Error! You've already posted the post you said you would post in the future. Please start registration over with a new post. Please don't post the post until we ask you to!";
	else if(postIsThere == "ERROR:PRIVATE")
		return "$20";
	else if(postIsThere == "ERROR:TIMELINE")
		return "$21";
	else if(postIsThere == "LOOKSFAKE") //TODO localize....
		return "$Sorry, your Facebook account does not look real and well established enough for Salmon to trust.";
	else if(postIsThere.indexOf("ERROR:ARGS") >= 0)
	{
		logError(niceCurTime()~": "~email~" beginRegistration() somehow called socnet checker with not enough arguments...");
		return "$4";
	}
	else if(postIsThere == "ERROR")
		return "$4";//"$Error! Couldn't access your social network account. Please start registration over.";
	
		
	JoiningUser theJoiner;
	theJoiner.osn_id = socNetID.dup;
	theJoiner.osn_post = post.dup;
	theJoiner.nationality = nationality.dup;
	theJoiner.osn_isRenren = isRenren;
	
	joining[email] = theJoiner;
	
	return "$5";//"$Ok! Registration is half-done. Now go post the post, and click Finish Registration after you have.";
}

//second half of registration process (with no recommendation): we check to see that the post is there.
string finishRegistration(string email)
{
	logError(niceCurTime()~": "~email~" finishRegistration()...");
	scope(exit) logError(niceCurTime()~": "~email~" finishRegistration() done.");
	
	if(email !in joining)
		return "$6";//"$Error! We don't have a record of your email having started the registration process.";
	
	JoiningUser curJoiner = joining[email];
	
	string thePost = to!string(curJoiner.osn_post);
	string theID = to!string(curJoiner.osn_id);
	string nationality = to!string(curJoiner.nationality);
	bool isRenren = curJoiner.osn_isRenren;
	
	
	string postIsThere = socialNetworkCheck(theID, thePost, isRenren);
	if(postIsThere == "ERROR")
	{
		//we're cancelling the registration, so this item can be forgotten.
		for(int i=0;i<joining[email].osn_post.length;i++)
			joining[email].osn_post[i]=0;
		for(int i=0;i<joining[email].osn_id.length;i++)
			joining[email].osn_id[i]=0;
		joining.remove(email);
		return "$4";//"$Error! Couldn't access your social network account. Please start registration over.";
	}
	else if(postIsThere == "YES")
	{
		//NOTE this is a base64 encoded ubyte[], because vibe and/or mongo is being difficult
		string osn_id_hash = secureHash(theID, isRenren);
		bool osn_is_renren = (theID.indexOf("renren.com") >=0 );
		int trust = 0;
		
		char[VPN_BASE_PW_LENGTH] thePassword;
		//NOTE oh actually... these passwords will be going over command lines. sooooo let's keep it simple.
		for(int i=0;i<VPN_BASE_PW_LENGTH;i++)
			thePassword[i] = cast(char)uniform(97, 122);
		
		auto uCol = dbClient.getCollection(clientCollection);
		uCol.insert(Bson
		([
			"osn_id_hash": Bson(osn_id_hash),
			"osn_is_renren": Bson(osn_is_renren),
			"trust": Bson(trust),
			 "banned": Bson(false),
			 "email": Bson(email),
			 "vpn_password": Bson(to!string(thePassword)),
			"nationality": Bson(nationality),
			"suspicion_complement_CN": Bson(1.0),
			"suspicion_complement_IR": Bson(1.0),
			 "penalty_points": Bson(1),
		 //just so they won't be null:
			"usage_score": Bson(0),
			"usage_score_last_applied": Bson(BsonDate.fromString("2002-02-02T10:01:00")),
			 "last_usage_value": Bson(0),
		 "previous_recommendation": Bson(BsonDate.fromString((Clock.currTime()-5.weeks).toISOExtString()))
		]));
		
		//it has succeeded, so this item can be forgotten.
		for(int i=0;i<joining[email].osn_post.length;i++)
			joining[email].osn_post[i]=0;
		for(int i=0;i<joining[email].osn_id.length;i++)
			joining[email].osn_id[i]=0;
		joining.remove(email);
		
		logInfo(niceCurTime()~": welcome, "~email~"! Joined with socnetid "~osn_id_hash~".");
		return to!string(thePassword)~"\n";
	}
	else
		return "$8";//"$We didn't see the post on your social network page. Be sure you posted exactly what you told us (check spelling). If you definitely posted it, it might just need a little more time to become visible - try again in a few seconds.";
}


string recdRegistration(string email, string nationality, string recCode)
{
	auto uCol = dbClient.getCollection(clientCollection);
	auto rCol = dbClient.getCollection(recCodesCollection);
	
	logError(niceCurTime()~": "~email~" recdRegistration()...");
	scope(exit) logError(niceCurTime()~": "~email~" recdRegistration() done.");
	
	//if email already in clients db or joining db, they can't register again
	if(uCol.count(["email": Bson(email)]) > 0 || email in joining)
		return "$1";//"$Error! This email address is already registered.";
	
	//look for the recommendation code they gave us
	int goToLevel;
	auto results = rCol.find(["recommendation": Bson(recCode)]);
	bool foundOne = false;
	string recommenderEmail;
	foreach(doc ; results)
	{
		foundOne = true;
		recommenderEmail = extractVibeString(doc["recommender"]);
		goToLevel = to!int(doc["go_to_level"]);
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
		return "$9$"~recCode;//"$Recommendation code "~recCode~" not found! Check for typos. Has it already been used?";
	
	//NOTE oh actually... these passwords will be going over command lines. sooooo let's keep it simple.
	char[VPN_BASE_PW_LENGTH] thePassword;
	for(int i=0;i<VPN_BASE_PW_LENGTH;i++)
		thePassword[i] = cast(char)uniform(97, 122);
	
	//ok, the code is there, so they get to join at trust level goToLevl!
	uCol.insert(Bson
	([
		//string: Bson
		"email": Bson(email),
		"trust": Bson(goToLevel),
		//"osn_id_hash": (osn_id_hash), NOTE in this case they just aren't associated with any osn account
		//"osn_is_renren": Bson(osn_is_renren), NOTE aren't associated with any osn account
		"suspicion_complement_CN": Bson(1.0),
		"suspicion_complement_IR": Bson(1.0),
		 "penalty_points": Bson(1),
		"banned": Bson(false),
		"my_recommender": Bson(recommenderEmail),
		 "previous_recommendation": Bson(BsonDate.fromString((Clock.currTime()-5.weeks).toISOExtString())),
		 "vpn_password": Bson(to!string(thePassword)),
		"nationality": Bson(nationality),
		//just so they aren't null:
		"usage_score": Bson(0),
		"usage_score_last_applied": Bson(BsonDate.fromString("2002-02-02T10:01:00")),
		 "last_usage_value": Bson(0)
	]));
	logInfo(niceCurTime()~": welcome, "~email~"! Recommended to trust level "
			~to!string(goToLevel)~" by "~recommenderEmail~".");
	
	rCol.remove(["recommendation": Bson(recCode)]);
	
	return to!string(thePassword)~"\n";
}




//characters that can be in the request string: avoid O 0 l 1 I i j 2 z etc)
const char[] validChars =
['a','b','c','d','e','f','g','h','k','m','n','r','t','v','x','y','2','3','4','5','6','7','8','9'];

//NOTE: here's the recommendation logic. you can only have one recommendation active in the database 
//at a time. we remove it when it gets used.
//if you do another request while one is still active, we tell you the old one, and say "go use this one".
//if you do another request and your previous one was used, and we're still in its waiting period (counting
//from time it was issued), we say "wait until <whenever>."
//if you do another request after the waiting period (and your previous code has been used),
//we give you a new code.

//they're asking us to generate and remember a code for them to give out
//email is email of the person asking for a code to give to a friend
string requestRecommendation(string email)
{
	auto uCol = dbClient.getCollection(clientCollection);
	auto rCol = dbClient.getCollection(recCodesCollection);
	
	logError(niceCurTime()~": "~email~" requestRecommendation()...");
	scope(exit) logError(niceCurTime()~": "~email~" requestRecommendation() done.");
	
	SysTime previous_recommendation;
	int trust;
	bool isBanned;
	
	auto results = uCol.find(["email": Bson(email)]);
	foreach(doc ; results)
	{
		isBanned = to!bool(doc["banned"]);
		previous_recommendation = (cast(BsonDate)doc["previous_recommendation"]).toSysTime();
		trust = to!int(doc["trust"]);
		break;
	}
	
	if(isBanned)
		return "$11";//"$Your account is permanently banned. If you aren't helping a government block servers, then we're sorry. Unfortunately, unless we had many more VPN servers to burn through, it's impossible to be 100% accurate with our bans. If you want to get a new account, get a recommendation code from a highly trusted user.";
	
	//check their trust level to make sure they're trusted enough to recommend. then, make sure
	//they haven't gotten a recommendation code too recently (where "too recently" is defined by
	//whether they're MAX or just highly trusted). if all that is fine, generate a random string,
	//put it in the ActiveCodes db, and return it.
	if(trust < HIGH_TRUST)
		return "$12";//"$Sorry! You can't recommend friends until you are highly trusted.";
		
	//check for a currently active code we gave this user...
	results = rCol.find(["recommender": Bson(cast(string)email)]);
	string activeCode = null;
	foreach(doc ; results)
	{
		activeCode = extractVibeString(doc["recommendation"]);
		break; //there should only be 1, so whatever
	}
	
	//if you do another request while one is still active, we tell you to use the old one.
	if(!(activeCode is null))
		return "$13$"~activeCode;//"$Your previous code "~activeCode~" has not yet been used and is still active. Please use that one.";
	
	//if you do another request and your previous one was used, and we're still in its waiting period
	//(counting from time it was issued), we say "wait until <whenever>."
	if(Clock.currTime - previous_recommendation < dur!"weeks"(4) && trust < MAX_TRUST)
		return "$14";//"$Sorry! You can only recommend once per month."; 
	if(Clock.currTime - previous_recommendation < dur!"days"(1) && trust == MAX_TRUST)
		return "$15";//"$Sorry! You can only recommend once per day.";
	
	uCol.update
	([
		"email": Bson(email)
	],[
		"$set": [	"previous_recommendation":
					 Bson(BsonDate.fromString(Clock.currTime().toISOExtString()))
	]]);
	
	//if you do another request after the waiting period (and your previous code has been used), we give 
	//you a new code. generate a code for them. make sure this code isn't already active, juuuust in case.
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
		"recommender": Bson(email),
		"go_to_level": Bson((trust == MAX_TRUST) ? TRUST_FROM_MAX_REC : TRUST_FROM_HIGH_REC)
	]));
	
	return to!string(theCode);
}

//NOTE this is only for already-existing users getting recommended; new user
//recommendations should be handled inside the registration process
string redeemRecommendation(string email, string recCode)
{
	logError(niceCurTime()~": "~email~" redeemRecommendation()...");
	scope(exit) logError(niceCurTime()~": "~email~" redeemRecommendation() done.");
	
	int goToLevel;
	auto rCol = dbClient.getCollection(recCodesCollection);
	auto results = rCol.find
	([
		"recommendation": Bson(recCode)
	]);
	bool foundOne = false;
	string recommenderEmail;
	foreach(doc ; results)
	{
		foundOne = true;
		recommenderEmail = extractVibeString(doc["recommender"]);
		goToLevel = to!int(doc["go_to_level"]);
		break; //there should only be 1, so whatever
	}
	if(!foundOne)
		return "$9$"~recCode;//"$Recommendation code "~recCode~" not found! Check for typos. Has it already been used?";
	
	auto uCol = dbClient.getCollection(clientCollection);
	//first, make sure they aren't getting recommended to below their current level!
	auto results2 = uCol.find(["email": Bson(email)]);
	int curTrust;
	foreach(doc ; results2)
	{
		curTrust = to!int(doc["trust"]);
		break; //there should only be 1, so whatever
	}
	if(curTrust >= goToLevel)
		return "$16";//"$This recommendation doesn't provide more trust than we already have for you! Give the code to someone who isn't already highly trusted.";
	
	uCol.update
	([
		"email": Bson(email)
	],[
		"$set": [	"trust": Bson(goToLevel),
				"usage_score": Bson(0),
				"my_recommender": Bson(recommenderEmail),
				"previous_recommendation":
						 Bson(BsonDate.fromString((Clock.currTime()-5.weeks).toISOExtString()))
	]]);
	
	rCol.remove(["recommendation": Bson(recCode)]);
	
	return "$17";//"$Recommendation successful!";
}


struct Group
{
	Bson myID;
	Bson[] users;
	double[] userSuspicionsCN;//just for suspicion diversity purposes.
	double[] userSuspicionsIR;//just for suspicion diversity purposes.
	string[] servers;//base64 encoded password hashes
	int level;
	bool isAlive;
	
	//just for demotion purposes: doesn't even get filled unless being queued for demotion
	string[] blockedServers;
}

//it's worth NOTE-ing that banned people do NOT have their VPN credentials revoked. that wouldn't
//really hurt the adversary, but it would DEFINITELY hurt real users.
void ban(string email)
{
	dbClient.getCollection(clientCollection).update
	([
		"email": Bson(email)
	],[
		"$set": ["banned": Bson(true)]
	]);
	
	logInfo("****************************************************");
	logInfo(niceCurTime()~": BANNED "~email~"!!!!");
	logInfo("****************************************************");
	
	//used to have userBanned[email] and emitPenaltyPoints(email) here...
}

/+FORMAT:
vpn base password (VPN_BASE_PW_LENGTH chars)
trust level (int)
last time user successfully generated a rec. code, (to!string(sse))
vpn_ip_addr vpn_psk offered_bw pem_cert_with_newlines_replaced_with_asterisks
vpn_ip_addr vpn_psk offered_bw pem_cert_with_newlines_replaced_with_asterisks
vpn_ip_addr vpn_psk offered_bw pem_cert_with_newlines_replaced_with_asterisks
...
+/
string getUserInfo(string email)
{
	auto uCol = dbClient.getCollection(clientCollection);
	auto sCol = dbClient.getCollection(serverCollection);
	auto results = uCol.find(["email": Bson(email)]);
	string retStr = "";

	logError(niceCurTime()~": "~email~" getUserInfo()...");
	scope(exit) logError(niceCurTime()~": "~email~" getUserInfo() done.");

	bool foundOne = false;
	foreach(doc ; results)
	{
		foundOne = true;
		retStr~= extractVibeString(doc["vpn_password"]);
		retStr~="\n";
		retStr~= to!string(to!int((doc["trust"])));
		retStr~="\n";
		
		SysTime lastRec = (cast(BsonDate)doc["previous_recommendation"]).toSysTime();
		
		retStr~=to!string(lastRec.toUnixTime());
		retStr~="\n";
		
		if(!doc["servers_given"].isNull())
		{
			foreach(thingy ; doc["servers_given"])
			{
				string curPH = extractVibeString(thingy);
				auto resServ = sCol.find(["password_hash": Bson(curPH)]);
				foreach(doc2 ; resServ)
				{
					//NOTE server_cert already has * in place of \n when put into mongo
					retStr~=(extractVibeString(doc2["current_ip"])     ~	" " ~
						 extractVibeString(doc2["psk"])               ~	" " ~
						 to!string(to!int(doc2["offered_bandwidth"])) ~	" " ~
						 extractVibeString(doc2["server_cert"])       ~	"\n");
					break;
				}
			}
		}
		
		break;
	}
	if(!foundOne)
		return "$6"; //we don't have a record of your email having started the registration process
		
	logError(niceCurTime()~": "~email~" getUserInfo() returning: "~(retStr.length > 30 ? retStr[0..30] : retStr));

	return retStr;
}


string appendAnyPurges(string email, string baseReply)
{
	auto results = dbClient.getCollection(clientCollection).find(["email": Bson(email)]);
	
	foreach(doc ; results)
	{
		if(doc["purge_list"].isNull())
			return baseReply;
		
		string toReturn = baseReply.chomp();
		
		foreach(thingy ; doc["purge_list"])
			toReturn ~= ("\nPURGE"~extractVibeString(thingy));
		
		logError(niceCurTime()~": Oh! appendAnyPurges appended something. We ended up with:");
		logError(toReturn);
		
		return toReturn; //should only be 1 result found, so this is yet another extraneous foreach
	}
	
	return "$6";//"we don't have a record of your email having started the reg process" <== good enough
}








//do requestBlockCheck to a whole bunch of servers.
//return: two lists (of pass hashes) of servers:
struct RequestBlockCheckAllResult
{
	//if not null, the blockCheck logic thinks we should drop everything and respond immediately with this.
	string overrideResponse;
	string[] unblocked;//unblocked AND fully functional
	string[] down;	//unblocked, they discovered they are NOT fully functional during the block check
}
struct BlockCheckQuery
{
	string serverPass;
	bool clientReportedError; //true ==> client couldn't connect, but could HTTPS GET
}
RequestBlockCheckAllResult requestBlockCheckAll(BlockCheckQuery[] toQuery, string userEmail, string userBasePW, string whichCountry)
{
	logError(niceCurTime()~": "~userEmail~" requestBlockCheckAll()...");
	scope(exit) logError(niceCurTime()~": "~userEmail~" requestBlockCheckAll() done.");
	
	RequestBlockCheckAllResult ret;
	foreach(query; toQuery)//TODO TODO parallel would be nice....
	{
		BlockStatus status = requestBlockCheck(query.serverPass, query.clientReportedError, userEmail,
									    userBasePW, whichCountry);
		if(status.offline && !status.blocked)
			ret.down ~= query.serverPass;
		else if(!status.offline && !status.blocked)
			ret.unblocked ~= query.serverPass;
		else
			logError(niceCurTime()~": not adding to ANY list!");
		if(status.responseString !is null)
		{
			ret.overrideResponse = status.responseString;
			return ret;
		}
	}
	return ret;
}

//does this usage score qualify for a promotion at this trust level? if so, apply
//the promotion to the given user, including zeroing uscore
//NOTE the suspicion parameter is suspicion, NOT suspicion_complement

void checkAndApplyPromotion(string userEmail, short trustLevel, int uScore, double suspicion)
{
	if(trustLevel+NEG_MAX >= scoreNeededShifted.length)
	{
		logInfo("Warning! User "~userEmail~" is somehow beyond MAX_TRUST!");
		return;
	}
	if(trustLevel+NEG_MAX < 0)
	{
		logInfo("Warning! User "~userEmail~" is somehow below NEG_MAX!");
		return;
	}
	int scoreNeeded = scoreNeededShifted[trustLevel+NEG_MAX];
	if(suspicion >= 0.3f) //NOTE this one should be the max of all suspicions
		scoreNeeded = 1999999999;
	
	if(uScore < scoreNeeded)
		return;
	
	//ok, they are high enough, so time to apply the promotion
	//...actually, promotion just entails giving them a level, if we're doing the
	//"you only join your current-level group when your current group gets demoted, or if
	//the user explicitly asks" thing.... so just trust++ and usage_score = 0 hooray!
	dbClient.getCollection(clientCollection).update
	([
		"email": Bson(userEmail)
	],[
		"$inc": ["trust": Bson(1)],
		"$set": ["usage_score": Bson(0)]
	]);
}

