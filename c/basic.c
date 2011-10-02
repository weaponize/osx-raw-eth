#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h> 
#include <net/if.h>

int main()
{

	char buf[ 11 ] = { 0 };
	int bpf = 0;
	int i;
	int buflen;
	void *pkt;
	int retval;
	ssize_t readlen;
	
	struct ifreq ifreq;

	for( i = 0; i < 99; i++ )
	{
	    sprintf( buf, "/dev/bpf%i", i );
	    bpf = open( buf, O_RDWR );

	    if( bpf != -1 )
	        break;
	}

	/*
	     BIOCSETIF      (struct ifreq) 
	Sets the hardware interface associate with the file.  This command must be performed before any packets can be read.  The device is indicated by name using the ifr_name field
	of the ifreq structure.  Additionally, performs the actions of BIOCFLUSH.
	*/
	strcpy(ifreq.ifr_name, "en0");
	if((retval = ioctl(bpf, BIOCSETIF, &ifreq))==-1) {
		fprintf(stderr, "BIOCSETIF %d\n", errno);
	}

	/* 
		BIOCGBLEN      (u_int) 
		Returns the required buffer length for reads on bpf files.
	*/
	if((retval = ioctl(bpf, BIOCGBLEN, &buflen))==-1) {
		fprintf(stderr, "BIOCGBLEN %d\n", errno);
	}

	/*
		BIOCSHDRCMPLT (u_int) 
		Set the status of the ``header complete'' flag.  Set to zero if the link level source address should be filled in automatically by the interface output routine.  Set to one if the link level source address will be written, as provided, to the wire.  This flag is initialized to zero by default.
	*/
	i = 1;
	if((retval = ioctl(bpf, BIOCSHDRCMPLT, &i))==-1) {
		fprintf(stderr, "BIOCSHDRCMPLT %d\n", errno);
	}
	
	
	/*
		BIOCSSEESENT (u_int) 
		Set the flag determining whether locally generated packets on the interface should be returned by BPF.  Set to zero to see only incoming packets on the interface.  Set to one to see packets originating locally and remotely on the interface.  This flag is initialized to one by default.
	*/
	i = 0;
	if((retval = ioctl(bpf, BIOCSSEESENT, &i))==-1) {
		fprintf(stderr, "BIOCSSEESENT %d\n", errno);
	}


	/*
		BIOCIMMEDIATE	 (u_int) Enable or disable "immediate mode", based on the truth value of the argument. When immediate mode is enabled, reads return immediately upon packet reception. Otherwise, a read will block until either the kernel buffer becomes full or a timeout occurs. This is useful for programs like rarpd(8) which must respond to messages in real time. The default for a new file is off
	*/
	i = 1;
	if((retval = ioctl(bpf, BIOCIMMEDIATE, &i))==-1) {
		fprintf(stderr, "BIOCIMMEDIATE %d\n", errno);
	}
	
	pkt = (void*)malloc(sizeof(char) * buflen);
	strcpy(pkt, "This is the packet!\0");
	
	if((retval = write(bpf, pkt, strlen(pkt)))==-1) {
		fprintf(stderr, "write() %d\n", errno);
	}
	
	memset(pkt,0, buflen);
	while(1) { 
		readlen = read(bpf, pkt, buflen);
	}
	
	return 0;
}
