module utility;

import vibe.d;

import std.digest.sha;
import std.base64;

import std.random;


const string theSalt = "[REDACTED]";

MongoClient dbClient;
SSLContext sslctx;
const string clientCollection = "salmonalpha.clients";
const string serverCollection = "salmonalpha.servers";
const string groupCollection = "salmonalpha.groups";
const string recCodesCollection = "salmonalpha.activerecommendations";

string niceCurTime()
{
	string rawTimeStr = to!string(Clock.currTime());
	if(rawTimeStr.lastIndexOf('.') == -1)
		return rawTimeStr;
	else
		return rawTimeStr[0 .. rawTimeStr.lastIndexOf('.')];
}


string secureHash(string input, bool isRenren)
{
	return Base64.encode(sha1Of(input ~ theSalt ~ (isRenren ? "RENREN" : "FACEBOOK")));
}

string serverPass(ubyte[] input)
{
	return Base64.encode(input);
}

string vibedTCPreadString(SSLStream theSSL)
{
	ubyte[2] readLen;
	theSSL.read(readLen);
	version(BigEndian)
	{
		ushort numBytes = *cast(ushort*)readLen.ptr;
		//NOTE: this is number of BYTES, in case we have unicode
	}
	else
	{
		ubyte[2] nBytesBytes;
		nBytesBytes[0] = readLen[1];
		nBytesBytes[1] = readLen[0];
		ushort numBytes = *cast(ushort*)nBytesBytes.ptr;
		//NOTE: this is number of BYTES, in case we have unicode
	}
	ubyte[] readStr = new ubyte[numBytes];
	theSSL.read(readStr);
	return cast(string)readStr;
}

string[] readLinesTLS(SSLStream theSSL)
{
	string wholeThing = vibedTCPreadString(theSSL);
	return splitLines(wholeThing);
}

string extractVibeString(Bson sillyInput)
{
	string sillyString = to!string(sillyInput);
	if(sillyString[0]=='"' && sillyString[$-1]=='"')
		return sillyString[1..$-1];
	else return sillyString;
}

ubyte[] vibedTCPreadBytes(TCPConnection con)
{
	ubyte[2] readLen;
	con.read(readLen);
	version(BigEndian)
	{
		ushort numBytes = *cast(ushort*)readLen.ptr; //NOTE: this is number of BYTES, in case we have unicode
	}
	else
	{
		ubyte[2] nBytesBytes;
		nBytesBytes[0] = readLen[1];
		nBytesBytes[1] = readLen[0];
		ushort numBytes = *cast(ushort*)nBytesBytes.ptr; //NOTE: this is number of BYTES, in case we have unicode
	}
	ubyte[] readStr = new ubyte[numBytes];
	con.read(readStr);
	return readStr;
}

string ughIPv4StringFromVibe(TCPConnection con)
{
	string start = con.peerAddress();
	if(start.indexOf("::ffff:")>=0)
		return start[start.indexOf("f:")+2..$];
	else
		return start;
}

auto numberFromBson(Bson bsonIn)
{		
	if(bsonIn.type == Bson.Type.long_)
		return bsonIn.get!long();
	else if(bsonIn.type == Bson.Type.int_)
		return bsonIn.get!int();
	else// if(bsonIn.type == Bson.Type.double_)
		return bsonIn.get!double();
}

//returns a random permutation of [1, 2, ..., range]
int[] knuthShuffle(int range)
{
	int[] ret = new int[range];
	for(int i=0;i<ret.length;i++)
		ret[i]=i+1;
	for(int i=0;i<ret.length;i++)
	{
		int dest = uniform(i, to!int(ret.length));
		int temp = ret[dest];
		ret[dest] = ret[i];
		ret[i] = temp;
	}
	return ret;
}

