#include <signal.h>
#include <unistd.h>

#include "global.h"

namespace global
{

bool quit = false;
bool userInt = false;
std::string pcapFile;
std::string interface;
std::string syslogServer;
uint32_t timeOut = 60;
std::string hostName;
pid_t pid = 0;
pcap_t *handle = nullptr;
std::unique_ptr<DnsCapture> dnsCapture;

/**
 * Processes the command line options
 * @return Sucess flag
 */
bool processCmdLine(int argc, char **argv)
{
	int c;
	const char *r, *i, *s, *t;
	r = i = s = t = nullptr;

	for (c = getopt (argc, argv, "r:i:s:t:"); c != -1; c = getopt (argc, argv, "r:i:s:t:"))
	{
		switch (c)
		{
			case 'r':
				r = optarg;
				break;

			case 'i':
				i = optarg;
				break;
				
			case 's':
				s = optarg;
				break;
				
			case 't':
				t = optarg;
				break;

			case '?':
			default:
				return false;
		}
	}

	/*
	one of ['r', 'i'] has to be specified
	if 'r' is set, then 'i' or 't' are invalid
	*/
	if (!(r || i) || (r && (i || t)))
	{
		return false;
	}

	if (r)
	{
		pcapFile = r;
	}

	if (i)
	{
		interface = i;
	}

	if (s)
	{
		syslogServer = s;
	}

	if (t)
	{
		int32_t tout = atoi(t);

		if (tout < 0)
		{
			return false;
		}

		timeOut = tout;
	}

	return true;
}

/**
 * Initializes necessary structures
 * @return Success flag
 */
bool initStructures(void)
{
	char hName[256];

	pid = getpid();

	if (gethostname(hName, sizeof(hName) / sizeof(hName[0])) != 0)
	{
		return false;
	}

	hName[255] = '\0';

	hostName = std::string(hName);

	return true;
}

/**
 * Prints the manual
 */
void manual(void)
{
	std::cout << "dns-export <-r pcapFile | -i interface [-t timeOut=60]> -s syslogServer" << std::endl;
}

void userIntHandler(int sig)
{
	userInt = true;
	pcap_breakloop(handle);
	(void)sig;
}

void quitHandler(int sig)
{
	quit = true;
	pcap_breakloop(handle);
	(void)sig;
}

/**
 * Sets signal handlers
 */
void setSignals(void)
{
	signal(SIGUSR1, userIntHandler);
	signal(SIGTERM, quitHandler);
}

/**
 * Masks signals for main thread
 * @return Success flag
 */
bool maskMainSignals(void)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGTERM);

	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
	{
		return false;
	}

	return true;
}

/**
 * Periodically sends SIGALRM
 */
void sender(void)
{
	setSignals();

	std::size_t slept = 0;

	while (!quit)
	{
		std::size_t toSleep = (slept > timeOut) ? 0 : timeOut - slept;
		sleep(toSleep);

		slept = 0;

		while (!dnsCapture->lockStatisticsMutex())
		{
			sleep(1);
			slept++;
		}
		
		if (!syslogServer.empty())
		{
			if (!dnsCapture->hasOpenSocket() && !dnsCapture->setSyslogServer())
			{
				std::cerr << "[ERR] Failed to open syslog server" << std::endl;
				dnsCapture->unlockStatisticsMutex();
				return;
			}

			dnsCapture->sendStatisticsToSyslogServer();
		}

		else
		{
			dnsCapture->dumpStatistics();
		}

		dnsCapture->unlockStatisticsMutex();
	}
}

} // global