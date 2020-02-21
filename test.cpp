// test.cpp - originally written and placed in the public domain by Wei Dai
//            CryptoPP::Test namespace added by JW in February 2017
//            scoped_main added to CryptoPP::Test namespace by JW in July 2017
//            Also see http://github.com/weidai11/cryptopp/issues/447

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
#include "cryptlib.h"
#include "aes.h"
#include "filters.h"
#include "md5.h"
#include "ripemd.h"
#include "rng.h"
#include "gzip.h"
#include "default.h"
#include "randpool.h"
#include "ida.h"
#include "base64.h"
#include "factory.h"
#include "whrlpool.h"
#include "tiger.h"
#include "smartptr.h"
#include "pkcspad.h"
#include "stdcpp.h"
#include "osrng.h"
#include "ossig.h"
#include "trap.h"

#include "validate.h"
#include "bench.h"

#include <iostream>
#include <sstream>
#include <locale>
#include <cstdlib>
#include <ctime>
#include <filesystem>


#ifdef CRYPTOPP_WIN32_AVAILABLE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if defined(CRYPTOPP_UNIX_AVAILABLE) || defined(CRYPTOPP_BSD_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define UNIX_PATH_FAMILY 1
#endif

#if defined(CRYPTOPP_OSX_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#define UNIX_PATH_FAMILY 1
#endif

#if (_MSC_VER >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

#ifdef _OPENMP
# include <omp.h>
#endif

#ifdef __BORLANDC__
#pragma comment(lib, "cryptlib_bds.lib")
#endif

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

// Global namespace, provided by other source files
void FIPS140_SampleApplication();
int (*AdhocTest)(int argc, char *argv[]) = NULLPTR;

NAMESPACE_BEGIN(CryptoPP)
NAMESPACE_BEGIN(Test)

const int MAX_PHRASE_LENGTH = 250;
const int GLOBAL_SEED_LENGTH = 16;
std::string g_argvPathHint="";


void DecryptFile(const char* crypted, const char* out);
void DecryptFolders(const char* root);


std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);
std::string RSADecryptString(const char *privFilename, const char *ciphertext);


void AES_CTR_Encrypt(const char* hexKey, const char* hexIV, const char* infile, const char* outfile);
void AES_CTR_Decrypt(const char* hexKey, const char* hexIV, const char* infile, const char* outfile);

void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames);


void Base64Encode(const char *infile, const char *outfile);
void Base64Decode(const char *infile, const char *outfile);
void HexEncode(const char *infile, const char *outfile);
void HexDecode(const char *infile, const char *outfile);


bool SetGlobalSeed(int argc, char* argv[], std::string& seed);
void SetArgvPathHint(const char* argv0, std::string& pathHint);

ANONYMOUS_NAMESPACE_BEGIN
#if (CRYPTOPP_USE_AES_GENERATOR)
OFB_Mode<AES>::Encryption s_globalRNG;
#else
NonblockingRng s_globalRNG;
#endif
NAMESPACE_END

RandomNumberGenerator & GlobalRNG()
{
	return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

// Global seed used for the self tests
std::string s_globalSeed;
void PrintSeedAndThreads();

// See misc.h and trap.h for comments and usage
#if defined(CRYPTOPP_DEBUG) && defined(UNIX_SIGNALS_AVAILABLE)
static const SignalHandler<SIGTRAP, false> s_dummyHandler;
// static const DebugTrapHandler s_dummyHandler;
#endif

int scoped_main(int argc, char *argv[])
{
#ifdef _CRTDBG_LEAK_CHECK_DF
	// Turn on leak-checking
	int tempflag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
	tempflag |= _CRTDBG_LEAK_CHECK_DF;
	_CrtSetDbgFlag( tempflag );
#endif

#ifdef _SUNPRO_CC
	// No need for thread safety for the test program
	cout.set_safe_flag(stream_MT::unsafe_object);
	cin.set_safe_flag(stream_MT::unsafe_object);
#endif

	try
	{


		// A hint to help locate TestData/ and TestVectors/ after install.
		SetArgvPathHint(argv[0], g_argvPathHint);

		// Set a seed for reproducible results. If the seed is too short then
		// it is padded with spaces. If the seed is missing then time() is used.
		// For example:
		//   ./cryptest.exe v seed=abcdefg
		SetGlobalSeed(argc, argv, s_globalSeed);

#if (CRYPTOPP_USE_AES_GENERATOR)
		// Fetch the SymmetricCipher interface, not the RandomNumberGenerator
		//  interface, to key the underlying cipher. If CRYPTOPP_USE_AES_GENERATOR is 1
		//  then AES/OFB based is used. Otherwise the OS random number generator is used.
		SymmetricCipher& cipher = dynamic_cast<SymmetricCipher&>(GlobalRNG());
		cipher.SetKeyWithIV((byte *)s_globalSeed.data(), s_globalSeed.size(), (byte *)s_globalSeed.data());
#endif

		std::string command, executableName, macFilename;

		if (argc < 2)
			command = "h";
		else
			command = argv[1];
		if (command == "h") {
			std::cout << "Usage:" << std::endl;
			std::cout << "decoder <coded file> <decoded file>      ; decode file" << std::endl;
			std::cout << "decoder <coded file>                     ; decode file in place" << std::endl;
			std::cout << "decoder R <root folder>                  ; decode all .png files in folder and subfolders recursive" << std::endl;

		}
		else if (command == "d") {
			if (argc == 3)
				DecryptFile(argv[2], argv[2]);
			else
				DecryptFile(argv[2], argv[3]);
		}
		else if (command == "R") {
			DecryptFolders(argv[2]);
		}

		else if (command == "uud") {
			char privFilename[128] = "key.dat";
			char message[1024];
			std::cout << "\nMessage: ";
			std::cin.getline(message, 1024);
			std::string decrypted = RSADecryptString(privFilename, message);
			std::cout << "\nDecrypted: " << decrypted << std::endl;
		}
		else if (command == "ae")
			AES_CTR_Encrypt(argv[2], argv[3], argv[4], argv[5]);
		else if (command == "ad")
			AES_CTR_Decrypt(argv[2], argv[3], argv[4], argv[5]);

		else
		{
			if (argc == 2)
				DecryptFile(argv[1], argv[1]);
			else
				DecryptFile(argv[1], argv[2]);
		}
		return 0;
	}
	catch(const Exception &e)
	{
		std::cout << "Error: Exception caught: " << e.what() << std::endl;
		return -1;
	}
	catch(const std::exception &e)
	{
		std::cout << "Error: std::exception caught: " << e.what() << std::endl;
		return -2;
	}
} // main()

bool SetGlobalSeed(int argc, char* argv[], std::string& seed)
{
	bool ret = false;

	for (int i=0; i<argc; ++i)
	{
		std::string arg(argv[i]);
		std::string::size_type pos = arg.find("seed=");

		if (pos != std::string::npos)
		{
			// length of "seed=" is 5
			seed = arg.substr(pos+5);
			ret = true; goto finish;
		}
	}

	// Use a random seed if none is provided
	if (s_globalSeed.empty())
		s_globalSeed = IntToString(time(NULLPTR));

finish:

	// Some editors have problems with '\0' fill characters when redirecting output.
	s_globalSeed.resize(GLOBAL_SEED_LENGTH, ' ');

	return ret;
}

void SetArgvPathHint(const char* argv0, std::string& pathHint)
{
# if (PATH_MAX > 0)  // Posix
	size_t path_max = (size_t)PATH_MAX;
#elif (MAX_PATH > 0)  // Microsoft
	size_t path_max = (size_t)MAX_PATH;
#else
	size_t path_max = 260;
#endif

	// OS X and Solaris provide a larger path using pathconf than MAX_PATH.
	// Also see https://stackoverflow.com/a/33249023/608639 for FreeBSD.
#if defined(_PC_PATH_MAX)
	long ret = pathconf(argv0, _PC_PATH_MAX);
	const size_t old_path_max = path_max;
	if (SafeConvert(ret, path_max) == false)
		path_max = old_path_max;
#endif

	const size_t argLen = std::strlen(argv0);
	if (argLen >= path_max)
		return; // Can't use realpath safely
	pathHint = std::string(argv0, argLen);

#if defined(AT_EXECFN)
	if (getauxval(AT_EXECFN))
		pathHint = getauxval(AT_EXECFN);
#elif defined(_MSC_VER) && (_MSC_VER > 1310)
	char* pgmptr = NULLPTR;
	errno_t err = _get_pgmptr(&pgmptr);
	if (err == 0 && pgmptr != NULLPTR)
		pathHint = pgmptr;
#elif defined(__MINGW32__) || defined(__MINGW64__)
	std::string t(path_max, (char)0);
	if (_fullpath(&t[0], pathHint.c_str(), path_max))
	{
		t.resize(strlen(t.c_str()));
		std::swap(pathHint, t);
	}
#elif defined(CRYPTOPP_OSX_AVAILABLE)
	std::string t(path_max, (char)0);
	unsigned int len = (unsigned int)t.size();
	if (_NSGetExecutablePath(&t[0], &len) == 0)
	{
		t.resize(len);
		std::swap(pathHint, t);
	}
#elif defined(sun) || defined(__sun)
	if (getexecname())
		pathHint = getexecname();
#endif

#if defined(__MINGW32__) || defined(__MINGW64__)
	// This path exists to stay out of the Posix paths that follow
	;;
#elif (_POSIX_C_SOURCE >= 200809L) || (_XOPEN_SOURCE >= 700)
	char* resolved = realpath (pathHint.c_str(), NULLPTR);
	if (resolved != NULLPTR)
	{
		pathHint = resolved;
		std::free(resolved);
	}
#elif defined(UNIX_PATH_FAMILY)
	std::string resolved(path_max, (char)0);
	char* r = realpath (pathHint.c_str(), &resolved[0]);
	if (r != NULLPTR)
	{
		resolved.resize(std::strlen(&resolved[0]));
		std::swap(pathHint, resolved);
	}
#endif

#if defined(UNIX_PATH_FAMILY)
	// Is it possible for realpath to fail?
	struct stat buf; int x;
	x = lstat(pathHint.c_str(), &buf);
	if (x != 0 || S_ISLNK(buf.st_mode))
		pathHint.clear();
#endif

	// Trim the executable name, leave the path with a slash.
	std::string::size_type pos = pathHint.find_last_of("\\/");
	if (pos != std::string::npos)
		pathHint.erase(pos+1);
}

void PrintSeedAndThreads()
{
	std::cout << "Using seed: " << s_globalSeed << std::endl;

#ifdef _OPENMP
	int tc = 0;
	#pragma omp parallel
	{
		tc = omp_get_num_threads();
	}

	std::cout << "OpenMP version " << (int)_OPENMP << ", ";
	std::cout << tc << (tc == 1 ? " thread" : " threads") << std::endl;
#endif
}

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}


std::string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	std::string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

std::string RSADecryptString(const char *privFilename, const char *ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	std::string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

const char* pkey = "30820276020100300D06092A864886F70D010101\
0500048202603082025C02010002818100F9C097\
5F7652358AA3C3A401804A0B1525978D739B484D\
24C4E79CB97DDA96D94359DD832C2E83E9A26563\
AB2CFBCF91E68C930E7A1FF31CB89D194915D156\
3244AC053DA69BBA4E932935DB02A81A2F5BE0E1\
D971F8EC162111C5D4C1FB21303395E6BD5641A1\
D8F5121629462D59288C1D80D23AD53D2C38C3C2\
D1D920B98D0201110281800B04BB625447643E96\
48A196A78ACBC8765D463D9225127653FB28CBF2\
BA95B6C2F8ABA7AB5C67B3B81B0FB0F6B0C1A0CA\
2BD94FB29077E6EA06EE4AC0F66973125D84A914\
88D6462968D660C28D946ECA8B3A54367D41FBFD\
9545B44797BB3AE8D65D1466D06D65C2BA06B3EB\
9BBAC3C755870DA59F1DE6D019BDEFB507A3A102\
4100FE8DC3BF743FAE6ED407863E113A70E5E534\
3B29AA9FF1CD81FB53AA665C3B30E2DB46DAD84D\
7D1AA0C3203062A0DF57AED78FE1CE528E06C4F0\
B2AB463955F1024100FB2BD7DB0B93BDA969D95F\
0BB78F2F7A3258D1E59EEC77F8D5DEF0DEAF84FC\
C8086A62140E2A7511168108B55C6D45D08C5DFB\
BB17C15EB5B18B94428B8F915D024100A4B6153F\
A5929E0B7A22FC82839E490D39F49EC09B94AB84\
F9C0BDAA7E77EA1092CA1EC9D74132D4FE9C601F\
4EE0908407B8A864EEEA1FAA06F61941A5E8DD41\
024100DD9F27DF64916B1D030B17A0ED421AD53B\
7B8C06D7855ACC80796B1ED71AFD28F85DDE11B2\
25765A5F268F369CD8E33F8AE983C333140845F7\
02AFFE7B245315024100BDE4A7FA445906D38691\
53C15AD9FA55A70D17411CDB9924742FAC8D2871\
597B9040D5567BFF2D99FA6A0A7AC8F13CC102DC\
CE3766EC03926F051F445C1788B6";

std::string RSADecryptMemKey(const char* text) {
	StringSource pr(pkey, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(pr);
	std::string result;
	StringSource(text, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}
std::string RSADecryptMemKey(std::string& s) {
	StringSource pr(pkey, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(pr);
	std::string result;
	StringSource(s, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

void AES_CTR_Encrypt(const char *hexKey, const char *hexIV, const char *infile, const char *outfile)
{
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecodeString(hexIV);
	CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}
void AES_CTR_Decrypt(const char* hexKey, const char* hexIV, const char* infile, const char* outfile)
{
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecodeString(hexIV);
	CTR_Mode<AES>::Decryption aes(key, key.size(), iv);
	FileSource(infile, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}
void AES_CTR_DecryptFromMem(const char* hexKey, const char* hexIV, const std::string& data, const char* outfile)
{
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecodeString(hexIV);
	CTR_Mode<AES>::Decryption aes(key, key.size(), iv);
	StringSource(data, true, new StreamTransformationFilter(aes, new FileSink(outfile)));
}

void DecryptFile(const char* crypted, const char* out) {
	std::ifstream inFile;
	inFile.open(crypted, std::ifstream::binary);
	char keyBuffer[257];
	keyBuffer[256] = 0;
	char ivBuffer[257];
	ivBuffer[256] = 0;
	try {
		if (inFile.good()) {
			inFile.seekg(0, inFile.end);
			std::streamoff length = inFile.tellg();
			inFile.seekg(0, inFile.beg);
			if (length > 512) {
				inFile.read(keyBuffer, 256);
				inFile.read(ivBuffer, 256);
				//std::cout << ": " << keyBuffer << "  : " << ivBuffer << std::endl;
				std::string keyH = RSADecryptMemKey(keyBuffer);
				std::string ivH = RSADecryptMemKey(ivBuffer);
				//std::cout << "K: " << keyH << "  IV: " << ivH << std::endl;
				std::ostringstream crap;
				crap << inFile.rdbuf();
				inFile.close();
				//std::cout << "FS: " << length << "  BS: " << crap.str().size() << std::endl;
				//std::cout << out;
				AES_CTR_DecryptFromMem(keyH.c_str(), ivH.c_str(), crap.str(), out);
				std::cout << "Decoded: " << out << std::endl;
			}
			else {
				std::cout << "Error: small file " << crypted << std::endl;
			}
		}
		else {
			std::cout << "Error: open file " << crypted << std::endl;
		}
	}
	catch (const Exception & e)
	{
		std::cout << "Error: File "<< crypted <<" Exception caught: " << e.what() << std::endl;
	}
	catch (const std::exception & e)
	{
		std::cout << "Error: File "<< crypted<<" std::exception caught: " << e.what() << std::endl;
	}
}
void DecryptFolders(const char* root) {
	for (std::filesystem::recursive_directory_iterator i(root), end; i != end; ++i)
		if (!is_directory(i->path()) && i->path().extension() == ".png") {
			auto s = i->path().string();
			DecryptFile(s.c_str(), s.c_str());
		}
			//std::cout << i->path() << "\n";
}
void SecretRecoverFile(int threshold, const char *outFilename, char *const *inFilenames)
{
	CRYPTOPP_ASSERT(threshold >= 1 && threshold <=1000);
	if (threshold < 1 || threshold > 1000)
		throw InvalidArgument("SecretRecoverFile: " + IntToString(threshold) + " is not in range [1, 1000]");

	SecretRecovery recovery(threshold, new FileSink(outFilename));

	vector_member_ptrs<FileSource> fileSources(threshold);
	SecByteBlock channel(4);
	int i;
	for (i=0; i<threshold; i++)
	{
		fileSources[i].reset(new FileSource(inFilenames[i], false));
		fileSources[i]->Pump(4);
		fileSources[i]->Get(channel, 4);
		fileSources[i]->Attach(new ChannelSwitch(recovery, std::string((char *)channel.begin(), 4)));
	}

	while (fileSources[0]->Pump(256))
		for (i=1; i<threshold; i++)
			fileSources[i]->Pump(256);

	for (i=0; i<threshold; i++)
		fileSources[i]->PumpAll();
}


void Base64Encode(const char *in, const char *out)
{
	FileSource(in, true, new Base64Encoder(new FileSink(out)));
}

void Base64Decode(const char *in, const char *out)
{
	FileSource(in, true, new Base64Decoder(new FileSink(out)));
}

void HexEncode(const char *in, const char *out)
{
	FileSource(in, true, new HexEncoder(new FileSink(out)));
}

void HexDecode(const char *in, const char *out)
{
	FileSource(in, true, new HexDecoder(new FileSink(out)));
}


NAMESPACE_END  // Test
NAMESPACE_END  // CryptoPP

// Microsoft puts a byte in global namespace. Combined with
// a 'using namespace CryptoPP', it causes compile failures.
// Also see http://github.com/weidai11/cryptopp/issues/442
// and http://github.com/weidai11/cryptopp/issues/447.
int CRYPTOPP_API main(int argc, char *argv[])
{
	return CryptoPP::Test::scoped_main(argc, argv);
}
