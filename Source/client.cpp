////////////INCLUDE COLOUR CODE///////////////////
#ifndef _COLORS_
#define _COLORS_
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST
#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST
#endif  /* _COLORS_ */
/////////////END OF INCLUDE COLOR CODE////////////////////
#include "chilkat/include/CkFtp2.h"



#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <iostream>
#include <unistd.h> 
#include <stdio.h> 
#include <stdlib.h>
#include <sstream> 
#include <fstream>

#include "cryptopp/idea.h"
using CryptoPP::IDEA;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/osrng.h"

using namespace std;
using namespace CryptoPP;


CkFtp2 ftp;


////////////////////////////////////////////
string IV_from_file,Key_from_file,ftp_host,ftp_name,ftp_password;
string hard_keys="65FD379515B4410BAA2EACAA1C0E865D";
string hard_IVs="30D37831B2FF9063";


string encrypt_conversation(string plain,string hard_keys,string hard_IVs);
string decrypt_conversation(string cipher,string hard_keys, string hard_IVs);
void menu(int sock);

////////////////////PRINT////////////////////

void Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource
   std::cout << label << ": " << encoded << std::endl;
}


/////////////////////////SEND_RECV_//////////////////////

string send_recv(int socket, string message, string comments)
{
int valread;
char buffer[1024] = {0};
string encrypted=encrypt_conversation(message.c_str(),hard_keys,hard_IVs);
send(socket , encrypted.c_str() , strlen(encrypted.c_str())+1 , 0 );
cout<<"[ Successfully send to Server ] "<<comments<<endl;
valread = read(socket , buffer, 1024); 
cout<<"[ Encrypted message from Authentication Server ] : ";
printf("%s\n",buffer ); 
encrypted=buffer;
string recovered=decrypt_conversation(encrypted,hard_keys,hard_IVs);
cout<<"[ Recovered message from Authentication Server ] : "<<recovered<<endl;
return recovered;
}




///////////////////////DECRYPT CONVERSATION//////////////////////////////


string decrypt_conversation(string cipher,string hard_keys,string hard_IVs){
string recovered;
string keys,IVs;

StringSource ss(hard_keys,true,new HexDecoder(new StringSink(keys)));
StringSource sss(hard_IVs,true,new HexDecoder(new StringSink(IVs)));

AutoSeededRandomPool prng;

SecByteBlock key((const byte*)keys.data(), keys.size());
SecByteBlock iv((const byte*)IVs.data(), IVs.size());
string rawcipher;
try
{
        StringSource ss2(cipher, true,
        new HexDecoder(
                new StringSink(rawcipher)
            ) // HexEncoder
        ); // StringSource


    OFB_Mode< IDEA >::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(rawcipher, true, 
        new StreamTransformationFilter(d,
            new StringSink(recovered)
        ) // StreamTransformationFilter
    ); // StringSource
}

catch(const CryptoPP::Exception& e)
{
    cerr << e.what() << endl;
    exit(1);
}
return recovered;
}

//////////////////////////KEY////////////REVERSE/////////////

string keyreverse(string plain){
string tmp,reverse;
cout<<"Before Reverse : "<<plain<<endl;
for(int i=0; i <= plain.length();i++)
{
	tmp[i]=plain[plain.length()-i];
	 reverse= reverse+tmp[i];
}
cout<<"After Reverse : "<< reverse<<endl;
return reverse;
}





///////////////////////ENCRYPT_ IDEA_KEY1///////////////

string encrypt_conversation(string plain,string hard_keys,string hard_IVs){

string keys,IVs;
StringSource ss(hard_keys,true,new HexDecoder(new StringSink(keys)));
StringSource sss(hard_IVs,true,new HexDecoder(new StringSink(IVs)));

AutoSeededRandomPool prng;

SecByteBlock key((const byte*)keys.data(), keys.size());
SecByteBlock iv((const byte*)IVs.data(), IVs.size());

string encoded,cipher;
try
{
//    cout << "Plain text: " << plain << endl;

    OFB_Mode< IDEA >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    // The StreamTransformationFilter adds padding
    //  as required. ECB and CBC Mode must be padded
    //  to the block size of the cipher.
    StringSource(plain, true, 
        new StreamTransformationFilter(e,
            new StringSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource
}
catch(const CryptoPP::Exception& e)
{
    cerr << e.what() << endl;
    exit(1);
}

/*********************************\
\*********************************/

// Pretty print
StringSource(cipher, true,
    new HexEncoder(
        new StringSink(encoded)
    ) // HexEncoder
); // StringSource

//cout << "Cipher text: " << encoded << endl;
return encoded;
}




////////////////////////SHA1/////////////////////////

string sha1string(string haha)
{
string digest="";
CryptoPP::SHA1 sha1;
CryptoPP::StringSource(haha, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
return digest;
}

//////////////////////////////VERIFY///////////////////

bool verify(string a, string b)
{

int result = strcmp(a.c_str(), b.c_str());
cout<<"Hold on, while we're verifying"<<endl;
if(result==0)
{
	cout<<FRED(BOLD("Matched"))<<endl;
	return true;
}
else
{
	cout<<FRED(BOLD("Failed"))<<endl;
	return false;
}
}


////////////////////////SOCKET///////////////////////////


int socket()
{
    cout<<"Enter Server IP ADDRESS"<<endl;
    string ip;
    cin>>ip;
    int PORT;
    do{
    cout<<"Enter port number"<<endl;
    cin>>PORT;
    if(PORT > 65535 || PORT <1)
    {
	cout<<"are you dumb ? the port range is \"0 - 65535\" "<<endl;
     }
    }while(PORT > 65535 || PORT < 1);

    int sock = 0, valread; 
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
	exit(0);
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)
    {
        printf("\nInvalid address/ Address not supported \n");
	exit(0);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
	exit(0);
        return -1;
    }
 	return sock;
}



void changepassword(int sock){
string pass,pass2,pass3;
cout<<"Enter your existing password"<<endl;
cout<<"We will not verify your existing password until we send it over network"<<endl;
cin>>pass;
while(pass.length() < 8  || pass.length() > 12 )
{
cout<<"Password requirement length 8 - 12"<<endl;
cin>>pass;
}

do
{
cout<<"Enter your new password"<<endl;
cin>>pass2;

while(pass2.length() < 8  || pass2.length() > 12 )
{
cout<<"Password requirement length 8 - 12"<<endl;
cin>>pass2;
}

cout<<"Reconfirm your password"<<endl;
cin>>pass3;

}while(pass2.compare(pass3) != 0);

char* how="???";
send_recv(sock,sha1string(pass),"Sending OLD Password over network");
send_recv(sock,sha1string(pass2),"Sending NEW Password over network");
string status=send_recv(sock,how,"Is the password have been changed ?");
if(status.compare("Changed")==0)
cout<<"Your password have been changed"<<endl;
else
cout<<"You have entered wrong current password"<<endl;
}


////////////////GRAB DATA/////////////////


string grabdata(string plain_file){
ifstream file (plain_file);
string totaldata,inputdata;
if (file.is_open())
{
int counter=0;
    while(getline (file,inputdata))
     {
		totaldata=totaldata+inputdata+"\n";
     }
    file.close();
}
cout<<totaldata<<endl;
return totaldata;
}


string savefile(string cipher){
   string str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
   string newstr;
   int pos;
   while(newstr.size() != 56) {
    pos = ((rand() % (str.size() - 1)));
    newstr += str.substr(pos,1);
   }
    cout<<newstr<<endl;

 ofstream my (newstr);
  if (my.is_open())
  {
    my <<cipher;
    my.close();
  }

   return newstr;
}

void file_upload(){
	cout<<"\n\n----------------------------\n\n\n"<<endl;
	string filename;
	system("ls | xargs -n 1 basename");
	cout<<"\n\n\n\n\n----------------------------"<<endl;
	cout<<"Enter the file you want to upload"<<endl;
	cin>>filename;
        cout<<"Encrypting File"<<endl;

	string keys=keyreverse(Key_from_file);
	string ivs=keyreverse(IV_from_file);
	string data=grabdata(filename);
        string encrypted_data=encrypt_conversation(data,keys,ivs);
	cout<<"Encrypted Data:"<<encrypted_data<<endl;
	string random_file=savefile(encrypted_data);
// Connect and login to the FTP server.
    bool success = ftp.Connect();
    success = ftp.UnlockComponent("Anything for 30-day trial");

        ftp.put_Hostname(ftp_host.c_str());
        ftp.put_Username(ftp_name.c_str());
        ftp.put_Password(ftp_password.c_str());

    //  Connect and login to the FTP server.
    success = ftp.Connect();
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }

   //  Change to the remote directory where the file will be uploaded.
    success = ftp.ChangeRemoteDir("AS");
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }

   //  Upload a file.
    const char *localFilename = random_file.c_str();
//    const char *remoteFilename = remotefile.c_str();

    success = ftp.PutFile(localFilename,filename.c_str());
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }
    success = ftp.Disconnect();
    std::cout << "File Uploaded!" << "\r\n";
    string rmcommand="rm " + random_file;
    system(rmcommand.c_str());

}

void file_download(){
// Connect and login to the FTP server.
    bool success = ftp.Connect();
    success = ftp.UnlockComponent("Anything for 30-day trial");
 if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }
        ftp.put_Hostname(ftp_host.c_str());
        ftp.put_Username(ftp_name.c_str());
        ftp.put_Password(ftp_password.c_str());

    success = ftp.Connect();
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }

 //  Change to the remote directory where the file will be downloaded
    success = ftp.ChangeRemoteDir("AS");
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        exit(1);
    }
	cout<<"\n\n----------------------------\n\n\n"<<endl;

    // The ListPattern property is our directory listing filter.
    // The default value is "*", which includes everything.
    std::cout << ftp.listPattern() << "\r\n";

    // To get file and sub-directory information, simply
    // loop from 0 to ftp.GetDirCount() - 1
    int i;
    int n;
    n = ftp.GetDirCount();
    if (n < 0) {
        std::cout << ftp.lastErrorText() << "\r\n";
  //      return;
    }

    if (n > 0) {
        for (i = 0; i <= n - 1; i++) {
            // Display the filename
            std::cout << ftp.getFilename(i) << "\r\n";
        }

    }
	string filename;
	cout<<"\n\n\n\n\n----------------------------"<<endl;
	cout<<"Enter the file you want to Download"<<endl;
	cin>>filename;

    const char *remoteFilename = filename.c_str();

    // Download a file.
    success = ftp.GetFile(remoteFilename,remoteFilename);
    if (success != true) {
        std::cout << ftp.lastErrorText() << "\r\n";
        return;
    }

    success = ftp.Disconnect();

    std::cout << "File Downloaded!" << "\r\n";

        cout<<"Decrypting File"<<endl;

	string keys=keyreverse(Key_from_file);
	string ivs=keyreverse(IV_from_file);
	string data=grabdata(filename);
	string plain=decrypt_conversation(data,keys,ivs);
	cout<<"-------------------------------------------------"<<endl;
	cout<<"---------------Decrypted Content-----------------"<<endl;
	cout<<"-------------------------------------------------"<<endl;
	cout<<"\n\n\n"<<endl;
	cout<<plain<<endl;
	cout<<"\n\n\n"<<endl;
	cout<<"-------------------------------------------------"<<endl;
	cout<<"-------------------------------------------------"<<endl;
	std::ofstream ofs(filename.c_str(), std::ofstream::trunc);
        ofs << plain;
        ofs.close();
}


////////////////////////////LOGGED IN MENU///////////////////////

void logged_menu(int sock)
{
string selection;
cout<<"1.Change Password"<<endl;
cout<<"2.Upload File"<<endl;
cout<<"3.Download File"<<endl;
cout<<"4.Log out"<<endl;
cin >> selection;
if(selection.compare("1")==0)
{
send_recv(sock,selection,"Sending Choice 1");
	changepassword(sock);
	logged_menu(sock);

}
else if(selection.compare("2")==0)
{
char* ask="Ask";
send_recv(sock,selection,"Sending Choice 2");
string status=send_recv(sock,ask,"Asking approval to run FTP Operation");
if(status.compare("Okay")!=0)
logged_menu(sock);


file_upload();
logged_menu(sock);
}
else if(selection.compare("3")==0)
{
char* ask="Ask";
send_recv(sock,selection,"Sending Choice 3 ");
string status=send_recv(sock,ask,"Asking approval to run FTP Operation");
if(status.compare("Okay")!=0)
logged_menu(sock);


file_download();
logged_menu(sock);
}
else
{
send_recv(sock,selection,"Sending Choice 4 ");
menu(sock);
}

}


///////////////////////AUTHENTICATION////////////////////

void Authentication(int socket){
cout<<"Login"<<endl;
string user,password;
cout<<"Enter your ID"<<endl;
cin>>user;
cout<<"Enter your password"<<endl;
cin>>password;
password=sha1string(password);
cout<<password<<endl;
send_recv(socket,user,"Sending UserID to Authentication Server");
send_recv(socket,password,"Sending Hash to Authentication Server");
//////////time stamp////////////
time_t current_time;
current_time = time(NULL);
int timestamp=current_time/60/60/24;
//////////////////////////////

stringstream ss;  
ss<<timestamp;
string s; 
ss>>s;
/////////////////////////////
string response=send_recv(socket,s,"Sending TimeStamp as representative to ask Server, everything received and waiting for authentication result?");
if (verify(response,"Verified") == true)
{
char *hello = "Received Wink > .. < ";
ftp_host=send_recv(socket,hello,"Asking for FTP HOSTNAME");
ftp_name=send_recv(socket,hello,"Asking for FTP ID");
ftp_password=send_recv(socket,hello,"Asking for FTP PASSWORD");
Key_from_file=send_recv(socket,hello,"Asking for IDEA KEY");
IV_from_file=send_recv(socket,hello,"Asking for IDEA IV");

cout<<"FTP CREDENTIAL"<<endl;
cout<<"FTP HOSTNAME: "<<ftp_host<<endl;
cout<<"FTP ID: "<<ftp_name<<endl;
cout<<"FTP PASSWORD: "<<ftp_password<<endl;
cout<<"IDEA KEY: "<<Key_from_file<<endl;
cout<<"IDEA IV: "<<IV_from_file<<endl;
	logged_menu(socket);
}
else
{
	menu(socket);
}}




///////////////////////////////////REGISTER////////////////////
void Register(int socket){
cout<<"Register"<<endl;
string user,password;
cout<<"Enter user name"<<endl;
cin>>user;
cout<<"Enter Password"<<endl;
cin>>password;
while(password.length() < 8  || password.length() > 12 )
{
cout<<"Password requirement length 8 - 12"<<endl;
cin>>password;
}
password=sha1string(password);
cout<<password<<endl;
send_recv(socket,user,"Sending UserID to Authentication Server");
send_recv(socket,password,"Sending Hash to Authentication Server");
//////////time stamp////////////
time_t current_time;
current_time = time(NULL);
int timestamp=current_time/60/60/24;
//////////////////////////////

stringstream ss;  
ss<<timestamp;
string s; 
ss>>s;
/////////////////////////////

string response=send_recv(socket,s,"Sending TimeStamp as representative to ask Server, everything received and waiting for authentication result?");

if (response.compare("Failed")==0)
{
cout<<"USED ID is USED by other user"<<endl;
}
menu(socket);
}






/////////////////////MENU/////////////////


void menu(int sock){
cout<<"1.Register"<<endl;
cout<<"2.Login"<<endl;
cout<<"3.Program Exit"<<endl;
string selection;
cin>>selection;
send_recv(sock,selection,"Sending my choice to Authentication Server");

if (selection.compare("1") ==0 )
	Register(sock);
else if(selection.compare("2")==0)
	Authentication(sock);
else
	exit(1);
}




//////////////////MAIN///////////


int main(){
int sock=socket();
menu(sock);
return 0;
}
