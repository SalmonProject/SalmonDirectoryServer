module client_censorproof_comm;

import client_db_logic;
import need_server;
import std.string;
import std.process;
import std.stdio;
import core.atomic;
import server;
import utility;
import std.conv;
//import stringtypes;

import vibe.d;

class MailMessage
{
public:
	string emailAddr;
	string randomStr;
	string content;
	this(string ea, string co, string rs)
	{
		emailAddr = ea;
		randomStr = rs;
		content = co;
	}
}

struct Weather 
{
	string text;
	double temperature; // °C
}

interface mydefi 
{
	// GET /weather -> responds {"text": "...", "temperature": ...}
	Weather getWeather();

	// PUT /location -> accepts {"location": "..."}
	@property void location(string location);

	// GET /location -> responds "..."
	@property string location();
	
	@queryParam("emailAddr", "addr") @queryParam("randomString", "rand") @queryParam("theBody", "body")
	string getEmail(string emailAddr, string randomString, string theBody);
}

string abridgeMessage(string theMessage)
{
	string printReplyRaw = null;
	bool wasChopped = false;
	if(theMessage.length > 30)
	{
		printReplyRaw = theMessage[0..30];
		wasChopped = true;
	}
	else
	{
		printReplyRaw = theMessage;
		wasChopped = false;
	}
	long nlInd = printReplyRaw.indexOf("\n");
	string printReply = (nlInd >= 0 ? printReplyRaw[0..nlInd] : printReplyRaw);
	if(wasChopped)
		printReply ~= "...";
	
	return printReply;
}

class defi : mydefi 
{
	private 
	{
		string m_location;
		static shared long messageCounter = 1;
	}

	Weather getWeather() { return Weather("sunny", 25); }

	@property void location(string location) { m_location = location; }
	@property string location() { return m_location; }
	
	string getEmail(string emailAddr, string randomString, string theBody)
	{
		if(randomString.length > 50)
			randomString = randomString[0..50];

		long curCounter = (atomicOp!"+="(defi.messageCounter, 1) - 1);
		
		logInfo("=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V=V");
		logInfo(niceCurTime()~": REST request #"~to!string(curCounter)~
									": email sender: "~emailAddr~
									", message: "~abridgeMessage(theBody));
		
		MailMessage toReply = parseReceivedMessage(emailAddr, randomString, splitLines(theBody));
		
		logInfo(niceCurTime()~": REST response #"~to!string(curCounter)~
									": email sender: "~emailAddr~
									", the reply: "~abridgeMessage(toReply.content));
		logInfo("=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^=^");		
		
		return toReply.emailAddr ~ "\n" ~ toReply.randomStr ~ "\n" ~toReply.content;
	}
}


MailMessage parseReceivedMessage(const string from, const string randomString, const string[] text)
{try{
	if(text[0].indexOf("beginRegistration")>=0)
	{
		//beginRegistration
		//example.facebookid.123
		//facebook
		//US
		//line 1 of post
		//another line of the post
		//etc
		if(text.length<5)
			return new MailMessage(from, "$Invalid beginRegistration format. Something has gone wrong with the Salmon client.", randomString);
		
		string socNetID = text[1];
		bool isRenren = (text[2]=="renren");
		string nationality = text[3];//should be CN, IR, etc
		
		//extract and clean up the social network post.
		//to keep things simple for calling the osn checker program over ssh:
		//remove all newlines, and the special characters below
		//(the osn checker is also configured to do these deletions)
		string post;
		for(int i=4;i<text.length;i++)
			post~=text[i];
		
		post = translate(post, ['z':'z'],
					  ['`', '"', '\\', '(', ')', '|', '$', '#', '&', '*', ';', '\'', '<', '>', '\n', ' ', '?', ':']);
		return new MailMessage(from, beginRegistration(from, socNetID, post, nationality, isRenren), randomString);
	}
	else if(text[0].indexOf("finishRegistration")>=0)
	{
		return new MailMessage(from, finishRegistration(from), randomString);
	}
	else if(text[0].indexOf("recdRegistration")>=0)
	{
		if(text.length<3)
		{
			return new MailMessage(from, "$Invalid recdRegistration format. Something has gone wrong with the Salmon client.", randomString);
		}
		//recdRegistration
		//US
		//RECCODE
		string nationality = text[1];
		string recCode = text[2];
		return new MailMessage(from, recdRegistration(from, nationality, recCode), randomString);
	}
	else if(text[0].indexOf("requestRecommendation")>=0)
	{
		return new MailMessage(from, requestRecommendation(from), randomString);
	}
	else if(text[0].indexOf("redeemRecommendation")>=0)
	{
		//redeemRecommendation
		//RECCODE
		if(text.length<2)
			return new MailMessage(from, "$Invalid redeemRegistration format. Something has gone wrong with the Salmon client.", randomString);
		
		return new MailMessage(from, redeemRecommendation(from, text[1]), randomString);
	}
	else if(text[0].indexOf("needServer")>=0)
	{
		//first, parse out their "tried these offline servers, and tried these weird servers"
		int curServerLine = 1;
		string[] triedLines = [];
		string[] errorLines = [];
		if(curServerLine < text.length && text[curServerLine].indexOf("^*tried:^*")>=0)
		{
			curServerLine++;
			for(;curServerLine < text.length && 
				text[curServerLine].indexOf("^*error:^*")<0
				;curServerLine++)
			{
				triedLines ~= text[curServerLine];
			}
		}
		if(curServerLine < text.length && text[curServerLine].indexOf("^*error:^*")>=0)
		{
			curServerLine++;
			for(;curServerLine < text.length; curServerLine++)
				errorLines ~= text[curServerLine];
		}
		
		logError(niceCurTime()~": About to call needServer() with triedLines = "~to!string(triedLines)~",  errorLines = "~to!string(errorLines));
		string theReply = needServer(from, triedLines, errorLines);
		logError(niceCurTime()~": needServer() returned.");
		if(theReply is null)
		{
			return new MailMessage(from, "$Error in directory server! The directory server picked a new VPN server for you, but failed to tell it to accept your login credentials. Most likely, the chosen VPN server went offline just after it was chosen.", randomString);
		}
		else
		{
			theReply = appendAnyPurges(from, theReply);
			return new MailMessage(from, theReply, randomString);
		}
	}
	else if(text[0].indexOf("EXAMININGVPNGATE")>=0)
	{
		string theReply = needServer(from, ["LETSGETSOMEVPNGATEUPINS"], []);
		return new MailMessage(from, theReply, randomString);
	}
	else if(text[0].indexOf("existingLogin")>=0)
	{
		return new MailMessage(from, getUserInfo(from), randomString);
	}
	else
	{
		return new MailMessage(from, "$"~text[0]~" is an invalid command. Something has gone wrong with the Salmon client.", randomString);
	}
}catch(Throwable e){logError("\n\n*********************************\nwhoooa exception thrown when parsing REST email request!!! Sender: "~from~", RS: "~randomString~",\n  message contents: ["~to!string(text)~"]\nexception:\n"~to!string(e));}
		return new MailMessage(from, "$Directory server internal error. Try again later, and please notify the Salmon Project that this error happened, if you can.", randomString);
}

