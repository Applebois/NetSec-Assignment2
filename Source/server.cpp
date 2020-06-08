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
#include <unistd.h> 
#include <sstream>  
#include <stdio.h> 
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <fstream>
#include <ctime>

#include "chilkat/include/CkFtp2.h"


#include "cryptopp/idea.h"
using CryptoPP::IDEA;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;


#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/idea.h"
using CryptoPP::IDEA;
#include "cryptopp/sha.h"

using namespace std;
using namespace CryptoPP;
CkFtp2 ftp;

/////////////////////////////

string IV_from_file,Key_from_file,ftp_host,ftp_name,ftp_password,registered_time;
string hard_keys="65FD379515B4410BAA2EACAA1C0E865D";
string hard_IVs="30D37831B2FF9063";

////////////////////////////

int main();



void listen_menu(int sock);
bool check_credential(string id,string password,int type);
string decrypt_conversation(string cipher,string hard_key,string hard_IVs);
string encrypt_conversation(string plain,string hard_key,string hard_IVs);

string recv_send(int new_socket, string message, string comments)
{
    int valread;
    char buffer[1024] = {0}; 
	string compare;
        valread = read( new_socket , buffer, 1024); 
	string recovered=decrypt_conversation(buffer,hard_keys,hard_IVs);
	cout<<"[ Incoming message from Client ] : "<<buffer<<endl;
	cout<<"[ Decryted Incoming content ] : "<<recovered<<endl;
	string encrypted=encrypt_conversation(message,hard_keys,hard_IVs);
    	send(new_socket , encrypted.c_str() , strlen(encrypted.c_str())+1 , 0 ); 
    	cout<<"[ Details ] "<<comments<<endl;
	return recovered;
}


///////////////////////ENCRYPT CONVERSATION//////////////////////////////
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
    cout << "Plain text: " << plain << endl;

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

cout << "[ Sending Encrypted Content over network ]" << encoded << endl;
return encoded;
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

/////////////////////////////////SOCKET////////////////////////////


int PORT;
int socket()
{
    do{
    cout<<"Enter port number to start the listener"<<endl;
    cin >> PORT;
     if(PORT > 65535 || PORT <1)
    { 
        cout<<"are you dumb ? the port range is \"1 - 65535\" "<<endl;
     }
    }while(PORT > 65535 || PORT < 1);

    printf ("[Server] Listening the port %d successfully.\n", PORT);
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
       perror("setsockopt");
       exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
	return new_socket ;
}

string Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource
   std::cout << label << ": " << encoded << std::endl;
	return encoded;
}


bool connect_ftp(){
	cout<<"Enter IP address of FTP Server"<<endl;
	cin>>ftp_host;
	cout<<"Enter FTP ID"<<endl;
	cin>>ftp_name;
	cout<<"Enter FTP Password"<<endl;
	cin>>ftp_password;
}

void register_account(int sock){
char *hello = "Received Wink > .. < ";
string id=recv_send(sock,hello,"Client's ID");
string password=recv_send(sock,hello,"Client's Hash Password");

AutoSeededRandomPool prng;
SecByteBlock key(IDEA::DEFAULT_KEYLENGTH);
SecByteBlock iv(IDEA::BLOCKSIZE);

prng.GenerateBlock(key, key.size());
prng.GenerateBlock(iv, sizeof(iv));
string EncodedKey=Print("key", std::string((const char*)key.begin(), key.size()));
string EncodedIV=Print("iv", std::string((const char*)iv.begin(), iv.size()));


  char date[9];
  time_t t = time(0);
  struct tm *tm;

  tm = gmtime(&t);
  strftime(date, sizeof(date), "%Y%m%d", tm);

string s=date;
cout<<s<<endl;
password = encrypt_conversation(password,hard_keys,hard_IVs);
EncodedKey = encrypt_conversation(EncodedKey,hard_keys,hard_IVs);
EncodedIV = encrypt_conversation(EncodedIV,hard_keys,hard_IVs);
s = encrypt_conversation(s,hard_keys,hard_IVs);
string data=id+":"+password+":"+EncodedKey+":"+EncodedIV+":"+s+":\n";

if (check_credential(id,password,1) == true)
{
char *fail ="Failed";
string password=recv_send(sock,fail,"Failed");
listen_menu(sock);
}
else if(check_credential(id,password,1)==false)
{
char *ver ="Verified";
string password=recv_send(sock,ver,"Verified");
}
cout<<"User INPUT "<<data<<endl;


ofstream outfile;
outfile.open("user.txt", std::ios_base::app); // append instead of overwrite
outfile << data; 
outfile.close();
cout<<"Waiting for user's selection"<<endl;
listen_menu(sock);		// listen function;

}



void changedpassword(string id,string password){
std::ifstream file("user.txt");
if(file.good())
{
cout<<"File found,verifying"<<endl;
}else
{
file.open ("user.txt", fstream::app);
}
std::string str;
string file_id,dump,total_data,pass;
while(!file.eof())
{
       getline(file,file_id,':');                                   ///Read words before :
       getline(file,pass,':');                                   ///Read words before :
       getline(file,dump);                                   ///Read words before :
       if(id.compare(file_id) == 0 )
       {
	password=encrypt_conversation(password,hard_keys,hard_IVs);
	total_data=total_data+file_id+":"+password+":"+dump+"\n";
       }
	else if(file_id.compare("")!=0)
	{
	total_data=total_data+file_id+":"+pass+":"+dump+"\n";
	}
}
   system("rm user.txt");
   std::ofstream ofs("user.txt", std::ofstream::trunc);
   ofs << total_data;
   ofs.close();
}




bool check_credential(string id,string password,int type){
std::ifstream file("user.txt");
int counter=0;
if(file.good())
{
cout<<"Reading user.txt file"<<endl;
}
else
{
counter=1;
file.open ("user.txt", fstream::app);
}


std::string str;
if (type==2)
{
while(!file.eof())
	{
       string file_id="",file_pass="",dump;
       Key_from_file,IV_from_file,registered_time="";
       getline(file,file_id,':');                                   ///Read words before :
       getline(file,file_pass,':');                                   ///Read words before :
       getline(file,Key_from_file,':');                                   ///Read words before :
       getline(file,IV_from_file,':');                                   ///Read words before :
       getline(file,registered_time,':');                                    ///Read after the first word dumps all trash value just to go to nextline
	getline(file,dump);

	 file_pass=decrypt_conversation(file_pass,hard_keys,hard_IVs);

	if(file_id.compare(id)==0 && password.compare(file_pass)==0){
	 Key_from_file=decrypt_conversation(Key_from_file,hard_keys,hard_IVs);
	 IV_from_file=decrypt_conversation(IV_from_file,hard_keys,hard_IVs);
	 registered_time=decrypt_conversation(registered_time,hard_keys,hard_IVs);

	cout<<"Matched"<<endl;
	file.close();
	return true;
	}

	}

file.close();
return false;

}

else if(type==1)
{

while(!file.eof())
{
	string dump;
	string file_a;
       getline(file,file_a,':');                                   ///Read words before :
       getline(file,dump);                                    ///Read after the first word dumps all trash valu$
       if(counter==1)
	{
		return false;
	}
       if(id.compare(file_a) == 0 )
       {
        cout<<"USER ID is used, Change another USER ID"<<endl;
	file.close();
	return true;
       }
}
file.close();
return false;
}
}


void renewKEY_IV(string id){
AutoSeededRandomPool prng;
SecByteBlock key(IDEA::DEFAULT_KEYLENGTH);
SecByteBlock iv(IDEA::BLOCKSIZE);
prng.GenerateBlock(key, key.size());
prng.GenerateBlock(iv, sizeof(iv));
Key_from_file=Print("key", std::string((const char*)key.begin(), key.size()));
IV_from_file=Print("iv", std::string((const char*)iv.begin(), iv.size()));
std::ifstream file("user.txt");
if(file.good())
{
cout<<"File found,verifying"<<endl;

}else
{
file.open ("user.txt", fstream::app);
}
std::string str,total_data;
while(!file.eof())
{
       string file_id,dump,pass,IVs,KEYs,stamp;
       getline(file,file_id,':');                                   ///Read words before :
       getline(file,pass,':');                                   ///Read words before :
       getline(file,KEYs,':');                                   ///Read words before :
       getline(file,IVs,':');                                   ///Read words before :
       getline(file,stamp,':');                                   ///Read words before :
       getline(file,dump);                                   ///Read words before :
       if(id.compare(file_id) == 0 )
       {
	total_data=total_data+file_id+":"+pass+":"+Key_from_file+":"+IV_from_file+":"+stamp+":"+"\n";
//        total_data=total_data+file_id+":"+pass+":"+Key_from_file+":"+IV_from_file+":"+stamp+":";
       }
        else if(file_id.compare("")!=0)
        {
        total_data=total_data+file_id+":"+pass+":"+KEYs+":"+IVs+":"+stamp+":"+"\n";
        }
}
   file.close();
   std::ofstream ofs("user.txt", std::ofstream::trunc);
   ofs << total_data;
   ofs.close();

}


bool login_account(int sock){
char *hello = "Received Wink > .. < ";
char *ver = "Verified";
char *fail = "Failed";
string id=recv_send(sock,hello,"Client's ID");
string password=recv_send(sock,hello,"Client's Hash Password");
bool check=check_credential(id,password,2);
if (check==true)
{
int i = std::stoi(registered_time);

  char date[9];
  time_t t = time(0);
  struct tm *tm;

  tm = gmtime(&t);
  strftime(date, sizeof(date), "%Y%m%d", tm);

   string s=date;
   cout<<s<<endl;
int b =std::stoi(s);

if( b - i >=200)	// if register date + 60 days equal or more than then renew KEY
{
cout<<"your IDEA KEY2 and IV is renew"<<endl;
renewKEY_IV(id);
}
string timestamp=recv_send(sock,ver,"Verified");
cout<<ftp_host<<endl;
recv_send(sock,ftp_host,"FTP HOSTNAME");
recv_send(sock,ftp_name,"FTP ID");
recv_send(sock,ftp_password,"FTP PASSWORD");
recv_send(sock,Key_from_file,"IDEA KEY");
recv_send(sock,IV_from_file,"IDEA IV");

string login_selection;
do{
login_selection=recv_send(sock,hello,"Received Login Menu Choice");

if(login_selection.compare("1")==0)
	{
		char *hello = "Received Wink > .. < ";
		char * ok="Changed";
		char * fail="Failed";
		string existpw=recv_send(sock,hello,"OLD PASSWORD");
		bool stat=check_credential(id,existpw,2);
		string newpw=recv_send(sock,hello,"New PASSWORD");
		if (stat==true)
		{
			changedpassword(id,newpw);
			recv_send(sock,ok,"Password changed");
		}
		else
		recv_send(sock,fail,"Password failed to change");


	}
	else if(login_selection.compare("2")==0)
	{
		if( b - i >= 1 )		//difference of 24hous
		{
		char* ok="Okay";
		recv_send(sock,ok,"Operation allowed");
		cout<<"File Upload Selected"<<endl;
		}else
		{
		char* fail="failed";
		recv_send(sock,fail,"Operation failed");
		cout<<"You're within 24 hours activiation,FTP operation is disabled"<<endl;
		}
	}
	else if(login_selection.compare("3")==0)
	{
		if( b - i >=1 )		//difference of 24 hours
		{
		char* ok="Okay";
		recv_send(sock,ok,"Received Login Menu Choice");
		cout<<"File Download Selected"<<endl;
		}else
		{
		char* fail="failed";
		recv_send(sock,fail,"Received Login Menu Choice");
		cout<<"You're within 24 hours activiation,FTP operation is disabled"<<endl;
		}
	}
	else if (login_selection.compare("4")==0)
	{
		listen_menu(sock);
	}
}while(login_selection.compare("4")!=0);

}
else
{
string timestamp=recv_send(sock,fail,"Failed");
listen_menu(sock);
}

}



void listen_menu(int sock){
char *hello = "Received Wink > .. < ";
string menu_selection=recv_send(sock,hello,"Client menu selection");
if(menu_selection.compare("1") == 0 )
        register_account(sock);
else if(menu_selection.compare("2") == 0)
        login_account(sock);
else if(menu_selection.compare("3")==0)
{
	cout<<"{Program Terminate}"<<endl;
        exit(1);
}
}


int main()
{
int sock=socket();
bool connection=connect_ftp();
listen_menu(sock);
return 0;
}
