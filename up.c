#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <errno.h> 
#include <string.h> 
#include <time.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/time.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define shift (argc--,argv++,argc>0?argv[0]:NULL)
#define ishift (argc--,argv++,argc>0?atoi(argv[0]):-1)
#define lshift (argc--,argv++,argc>0?atol(argv[0]):-1)

#define OFFSETOF(s,m) (int)((void*)(&s.m)-(void*)&s)

#define MAX_PAYLOAD 16384
#define HEADER_LEN 12

#define ACK_PACKET_ACK 'A'
#define NAK_PACKET_NAK 'N'
#define PAYLOAD_PACKET 'P'
#define EOF_PACKET     'E'

int payload_len = 1400;
int debug = 1;
int show_stats = 1;

struct packet {
	char type;
	char reserved[3];
	int32_t seq;
	int16_t length;
	unsigned char payload[MAX_PAYLOAD];
};

typedef struct packet packet_t;

struct packet_queue {
	struct packet_queue *next;
	time_t ts;
	packet_t *packet;
	long retransmits;
};

typedef struct packet_queue packet_queue_t;

struct stats {
	struct timeval start;
	struct timeval transfer_start;
	struct timeval transfer_end;
	long reads;
	long bytes;
	long packets_sent;
	long packets_received;
	long retransmits;
};

typedef struct stats stats_t;

#define PACKET_QUEUE_LIMIT 1000

pid_t ssh_run_server(char *remote, char *host, int port) {
	pid_t pid = fork();
	if (pid == 0) {
		char cmd[1024];
		if (debug > 0) printf("RUN SERVER: ssh %s up --receive %s %d\n", remote, host, port);
		close(0);
		sprintf(cmd, "/home/adf/up/up --debug=%d --receive %s %d >/tmp/up.out 2>&1", 9, host, port);
		execl("/usr/bin/ssh", "-T", remote, cmd, NULL);
	}
	return pid;
}

void hex_dump(unsigned char *mem, int len) {
	int i, o = 0;
	while (len > 0) {
		printf("%08x", o);
		for (i = 0; i < 32 && len > 0; i++, len--) {
			printf(" %02x", (int) *mem);
			mem++;
		}
		o += 32;
		printf("\n");
	}
	fflush(stdout);
}

// add packet to queue, in sequence order
// TODO: We only add packets in order, so the more packets are added the more traversal
// we need to do, if we knew where the last one was, we could append easily.
packet_queue_t *insert_packet_in_queue(packet_queue_t *this, packet_queue_t **head, packet_queue_t **tail, long seq) {
	packet_queue_t *insert = *head;
	packet_queue_t *prev = 0;

	if (debug > 4) printf("INSERT_PACKET\n");
	
	// Find insertion point
	while (insert && insert->packet->seq < seq) {
		prev = insert;
		insert = insert->next;
	}

	// our next is the insertion point (may be null)
	this->next = insert;

	if (insert) {
		// Insert packet into list
		if (prev) {
			prev->next = this;  // insert after previous
		} else {
			*head = this;		// insert at top of list
		}
	} else {
		// Append packet to possibly empty list
		if (prev) {
			*tail = prev->next = this;	// prev is last entry
		} else {
			*tail = *head = this;		// was empty list
		}
	}

	return this;
}

// add packet to end of queue.                                                                                      
packet_queue_t *append_packet_to_queue(packet_queue_t *this, packet_queue_t **head, packet_queue_t **tail, long seq) { 
	if (debug > 4) printf("APPEND_PACKET\n");
	this->next = NULL;
	return *head ? (*tail = (*tail)->next = this) : (*tail = *head = this);
}

void dump_queue(packet_queue_t *head, packet_queue_t *tail, int queued) {
	printf(" PACKET QUEUE LENGTH %d HEAD %p TAIL %p\n", queued, head, tail);
	packet_queue_t *entry = head;
	while (entry) {
		printf("  ENTRY %11p NEXT %11p PACKET %11p TYPE %c SEQ %ld LENGTH %4d PAYLOAD %11p\n", entry, entry->next, entry->packet, entry->packet->type, (long)entry->packet->seq, entry->packet->length, entry->packet->payload);
		entry = entry->next;
	}
}

// Remove acked packet. Note: If we receive an ACK for seq 10, we know the
// server has accepted and acknowledged all packets up to and including 10
// even though we may not have received the ack, so we treat any packet whos
// sequense is less than or equal to this ack, as acknowledged, and remove it
// from the list.
void remove_acked_packets_from_queue(packet_queue_t **head, packet_queue_t **tail, long seq, int *queued) {
	if (debug > 4) printf("REMOVE_ACKED_PACKETS\n");
	packet_queue_t *entry = *head;
	packet_queue_t *prev = NULL;
	while (entry) {
		if (debug > 8) printf("ENTRY %p SEQ %ld ACK %ld\n", entry, (long)entry->packet->seq, seq);
		if (entry->packet->seq <= seq) {
			packet_queue_t *e = entry;
			if (debug > 4) dump_queue(*head, *tail, *queued);
			if (debug > 5) printf("REMOVE %p ACKED PACKET %p: TYPE:%c SEQ:%ld LENGTH:%d\n", entry, entry->packet, entry->packet->type, (long)entry->packet->seq, entry->packet->length);
			if (debug > 8) printf("PREV %p HEAD %p TAIL %p NEXT %p\n", prev, *head, *tail, entry->next);
			if (prev) {
				prev->next = entry->next;
			} else {
				*head = entry->next;
			}
			if (entry == *tail) {
				*tail = prev;
			}
			(*queued)--;
			entry = entry->next; // prev is the same as before
			free(e->packet);
			free(e);
			if (debug > 4) dump_queue(*head, *tail, *queued);
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

packet_queue_t *find_packet_in_queue(packet_queue_t *entry, long seq) {
printf("FIND_PACKET\n");
	while (entry && entry->packet->seq != seq) {
		entry = entry->next;
	}
	return entry;
}

///////////////////////////////////////////////////////////////////////////////////
// UP Server
///////////////////////////////////////////////////////////////////////////////////

// up --receive server-ip port [client-ip]
int up_server(int argc, char **argv) {
	struct sockaddr_in addr, caddr;
	int seq_w = 0;
	char *ip;
	int port;
	socklen_t len;
	int n;
	int sockfd;
	int eof = 0;
	packet_t *packet = NULL;

	packet_queue_t *packet_queue = NULL;
	packet_queue_t *queue_tail = NULL;
	int queued = 0;

	// Parse arguments
	ip = shift;
	port = ishift;

	// Open Socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket creation failed");
		return EXIT_FAILURE;
	}

	// Initialise listen address
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	// Bind listening socket
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind failed");
		return EXIT_FAILURE;
	}

	if (debug > 5) printf("SOCKET %x LISTENING ON %lx:%d\n", sockfd, (unsigned long)addr.sin_addr.s_addr, port);

	// Initialise client address (we don't know it yet)
	memset(&caddr, 0, sizeof(struct sockaddr_in));
	caddr.sin_family = AF_INET;
	caddr.sin_port = htons(port);
	caddr.sin_addr.s_addr = INADDR_ANY;

	while (!eof) {
		if (debug > 8) printf("NOT DONE\n");

		// Drain packet queue if we already have the next sequence of packets
		while (packet_queue && packet_queue->packet->seq == seq_w) {
			if (debug > 5) printf("DRAIN QUEUE\n");

			// remove packet from the queue
			packet_queue_t *this = packet_queue;
			packet_queue = packet_queue->next;
			if (!packet_queue) queue_tail = NULL;
			queued --;

			// TODO: Write packet to file
			seq_w++;
			if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", this->packet->type, this->packet->seq, this->packet->payload, this->packet->length);

			// Free packet
			free(this->packet);
			free(this);

			if (debug > 4) dump_queue(packet_queue, queue_tail, queued);
		}

		// Allocate a packet buffer if needed
		if (!packet) {
			if ((packet = malloc(HEADER_LEN + payload_len)) == NULL) {
				perror("allocating payload buffer");
				return EXIT_FAILURE;
			}
			if (debug > 8) printf("ALLOCATED BUFFER %p LENGTH %d\n", packet, HEADER_LEN + payload_len);
		}

		len = sizeof(caddr);
		if (debug > 5) printf("RECV FROM %lx:%d...\n", (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
		if ((n = recvfrom(sockfd, packet, HEADER_LEN + payload_len, 0, (struct sockaddr *) &caddr, &len)) < 0) {

			perror("recvfrom");
			printf("n:%d errno:%d\n", n, errno);
			sleep(1);

		} else {

			if (debug > 5) {
				printf("SERVER RECV: type:%c seq:%ld len:%d PAYLOAD LENGTH %d FROM %lx:%d\n", packet->type, (long)packet->seq, n, packet->length, (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
				printf("PACKET SEQ %d SEQ_W %d\n", packet->seq, seq_w);
			}

			if (packet->type == 'S') {			// client sent SYN
				packet_t syn;
				syn.type = 'S';
				if (debug > 0) printf("SERVER SYN: TYPE:%c LENGTH:%d TO %lx:%d\n", syn.type, OFFSETOF(syn,reserved), (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
				sendto(sockfd, &syn, OFFSETOF(syn,reserved), 0, (struct sockaddr *) &caddr, len);
			}
			else if (packet->seq == seq_w) {
				if (packet->type == 'E') {
					// EOF
					if (debug > 0) printf("EOF\n");
					eof = 1;
				} else {
					// write data to file
					if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", packet->type, packet->seq, packet->payload, packet->length);
					if (packet->length) {
						if (debug > 5) hex_dump(packet->payload, packet->length);
					}
				}
				seq_w++;

				// Ack this packet
				{
					packet_t ack;
					ack.type = 'A';
					ack.reserved[0] = ack.reserved[1] = ack.reserved[2] = 0;
					ack.seq = packet->seq;
					ack.length = 0;
					if (debug > 0) printf("SERVER ACK: type:%c seq:%ld len:%d TO %lx:%d\n", ack.type, (long)ack.seq, OFFSETOF(ack,length), (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
					sendto(sockfd, &ack, OFFSETOF(ack,length), 0, (struct sockaddr *) &caddr, len);
				}
			}
			else if (packet->seq > seq_w) {
				// only store packets not already written, to the queue, and only if room
				packet_queue_t *this = NULL;
				if (queued < PACKET_QUEUE_LIMIT && (this = malloc(sizeof (packet_queue_t)))) {

					this->ts = time(0);
					packet = this->packet = realloc(packet, HEADER_LEN + packet->length);
					this->retransmits = 0;

					this = insert_packet_in_queue(this, &packet_queue, &queue_tail, packet->seq);
					if (this) {
						queued++;
						if (debug > 4) dump_queue(packet_queue, queue_tail, queued);
						if (debug > 5) printf("SERVER QUEUE PACKET [%d]: type%c seq:%ld len:%d FROM %lx:%d", queued, packet->type, (long)packet->seq, n, (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
					}

					packet = NULL;
				} else {
					// drop packet, queue full
					// TODO: Note, atm this drops the just received packet, but should it
					// drop the highest sequence packet instead?
				}

				// NAK packet sequence not received
				{
					packet_t nack;
					nack.type = 'N';
					nack.reserved[0] = nack.reserved[1] = nack.reserved[2] = 0;
					nack.seq = seq_w;
					if (debug > 0) printf("SERVER NACK: type:%c seq:%ld len:%d TO %lx:%d\n", nack.type, (long)nack.seq, OFFSETOF(nack,length), (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
					sendto(sockfd, &nack, OFFSETOF(nack,length), 0, (struct sockaddr *) &caddr, len);
				}
			} else {
				// ACK old packets (to tell client to stop sending them)
				{
					packet_t ack;
					ack.type = 'A';
					ack.reserved[0] = ack.reserved[1] = ack.reserved[2] = 0;
					ack.seq = packet->seq;
					if (debug > 0) printf("SERVER RESEND ACK: type:%c seq:%ld len:%d TO %lx:%d\n", ack.type, (long)ack.seq, OFFSETOF(ack,length), (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
					sendto(sockfd, &ack, OFFSETOF(ack,length), 0, (struct sockaddr *) &caddr, len);
				}
			}
		}
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////
// UP Client
/////////////////////////////////////////////////////////////////////////////////

// up ip port
// up user@host port - TODO over ssh
int up_client(int argc, char **argv) {
	packet_t *packet = NULL;
	struct sockaddr_in addr;
	int seq = 0;
	long offset = 0;
	int sockfd;
	int n;
	int len;
	packet_queue_t *packet_queue = NULL;
	packet_queue_t *queue_tail = NULL;
	int queued = 0;
	int eof = 0;
	char *host;
	pid_t server;
	char *remote;
	int port;
	int starting = 1;
	stats_t stats;

	// Initialise statistics
	memset(&stats, 0, sizeof(stats));
	gettimeofday(&stats.start, NULL);

	/* Args: <address> <port> */
	remote = shift;
	port = ishift;

	if (debug > 5) printf("CLIENT: REMOTE IS %s:%d\n", remote, port);

	// Find host name if user@host format
	host = strchr(remote,'@');
	host = host ? ++host : remote;

	// possibly run the server via ssh
	if (host != remote) {
		server = ssh_run_server(remote, host, port);
	}

	// Open Socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket creation failed");
		return EXIT_FAILURE;
	}

	// Initialise send to address
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (!inet_aton(host, &addr.sin_addr)) {
		perror("invalid address");
		return EXIT_FAILURE;
	}

	// Read standard input
	while (!eof || queued) {

		if (debug > 4) printf("-- eof:%d queued:%d starting:%d\n", eof, queued, starting);

		if (starting) {
			packet_t syn;
			syn.type = 'S';
			if (debug > 0) printf("CLIENT SYN: TYPE:%c LEN:%d TO %lx:%d\n", syn.type, OFFSETOF(syn,reserved), (unsigned long)addr.sin_addr.s_addr, ntohs(addr.sin_port));
			sendto(sockfd, &syn, OFFSETOF(syn,reserved), 0, (struct sockaddr *) &addr, len);
			stats.packets_sent++;
		}

		// As long as the packet queue is not full, read from standard input
		// and send to server, adding packet to packet queue
		if (!starting && !eof && queued < PACKET_QUEUE_LIMIT) {
			
			// Allocate a packet buffer
			if (!packet) {
				if ((packet = malloc(HEADER_LEN + payload_len)) == NULL) {
					perror("allocating payload buffer");
					return EXIT_FAILURE;
				}
				if (debug > 8) printf("ALLOCATED PACKET BUFFER: %p LENGTH %d\n", packet, HEADER_LEN + payload_len);
			}

			// read data from stdin
			if (debug > 5) printf("READ STANDARD INPUT\n");
			n = read(0, &(packet->payload), payload_len);
			if (n >= 0) {
				if (debug > 5) printf("READ %d BYTES FROM STDIN OFFSET %ld\n", n, stats.bytes);
				if (debug > 5) hex_dump(packet->payload, n);
				stats.bytes += n;
				if (n == 0) eof = 1;

				packet->type = eof ? EOF_PACKET : PAYLOAD_PACKET;
				packet->seq = seq++;
				packet->length = n;
				if (debug > 5) printf("CLIENT SEND: SEQ:%ld LENGTH:%d\n", (long)packet->seq, packet->length);

				// Add packet to waiting for ack queue
				if (debug > 8) printf("ALLOCATE QUEUE ENTRY\n");
				packet_queue_t *this = malloc(sizeof(packet_queue_t));
				this->ts = time(0);
				if (debug > 8) printf("REALLOCATE QUEUED PACKET %p TO LENGTH %d\n", packet, HEADER_LEN + packet->length);
				packet = this->packet = realloc(packet, HEADER_LEN + packet->length);
				if (debug > 8) printf("DONE REALLOCATE: NEW PACKET %p\n", packet);
				this->retransmits = 0;

				if (debug > 8) printf("ADD PACKET TO QUEUE %p\n", this);
				this = append_packet_to_queue(this, &packet_queue, &queue_tail, packet->seq);
				if (this) {
					queued++;
					if (debug > 4) dump_queue(packet_queue, queue_tail, queued);
					if (debug > 8) printf("QUEUE ENTRY %p COUNT %d\n", this, queued);
					if (debug > 5) printf("CLIENT QUEUE PACKET [%p]: TYPE:%c SEQ:%ld LENGTH:%d\n", packet, packet->type, (long)packet->seq, packet->length);
				} else {
					perror("adding packet to queue");
					return EXIT_FAILURE;
				}

				// Send payload
				if (debug > 0) printf("SEND PACKET [%p]: TYPE:%c SEQ:%ld LENGTH:%d TO %lx:%d\n", packet, packet->type, (long)packet->seq, packet->length, (unsigned long)addr.sin_addr.s_addr, ntohs(addr.sin_port));
				sendto(sockfd, packet, HEADER_LEN + n, 0, (struct sockaddr *) &addr, sizeof(addr));
				stats.packets_sent++;
				if (debug > 5) printf("SEND DONE\n");

				// We gave the packet to the packet queue
				packet = NULL;
			} else {
				perror("reading standard input");
				return EXIT_FAILURE;
			}
		}

		if (queued || starting) {

			if (debug > 5) printf("QUEUE SIZE %d\n", queued);

			// Allocate a packet buffer
			if (!packet) {
				if ((packet = malloc(HEADER_LEN + payload_len)) == NULL) {
					perror("allocating payload buffer");
					return EXIT_FAILURE;
				}
				if (debug > 8) printf("ALLOCATED PACKET BUFFER: %p LENGTH %d\n", packet, HEADER_LEN + payload_len);
			}

			if (debug > 5) printf("RECV PACKET\n");
			len = sizeof(addr);
			n = recvfrom(sockfd, packet, HEADER_LEN + payload_len, eof ? 0 : MSG_DONTWAIT, (struct sockaddr *) &addr, &len);
			if (n == -1) {
				if (errno == EAGAIN) {
					if (debug > 1) printf("RESPONSE: NO DATA\n");
					n = 0;
				} else {
					perror("recvfrom");
					return EXIT_FAILURE;
				}
			}

			if (n > 0) {
				if (debug > 0) printf("RESPONSE: TYPE:%c SEQ:%ld LEN:%d LENGTH:%d\n", packet->type, (long)packet->seq, n, n >= 12 ? packet->length : 0);
				stats.packets_received++;

				// Process packet
				switch(packet->type) {
				case 'A': // handle ack 
					remove_acked_packets_from_queue(&packet_queue, &queue_tail, packet->seq, &queued);
					break;
				case 'S': // server has started
					starting = 0;
					gettimeofday(&stats.transfer_start, NULL);
					break;
				case 'N': // handle nack
					{
						packet_queue_t *entry = find_packet_in_queue(packet_queue, packet->seq);
						if (entry) {
							// resend this packet
							if (debug > 5) printf("RESEND NACKED PACKET [%d]: TYPE:%c SEQ:%ld LENGTH:%d\n", queued, entry->packet->type, (long)entry->packet->seq, entry->packet->length);
							sendto(sockfd, entry->packet, HEADER_LEN + entry->packet->length, 0, (struct sockaddr *) &addr, sizeof(addr));
							stats.packets_sent++;
							stats.retransmits++;
							entry->retransmits++;
						}
					}
					break;
				}
			} else {
				if (starting) {
					if (debug > 8) printf("NO RESPONSE usleep %dms\n", starting * 10);
					usleep(10 * starting * 1000);
					if (starting < 100) starting *= 2;
				}
			}
		}
	}

	if (n < 0) {
		perror("read");
		return EXIT_FAILURE;
	}

	gettimeofday(&stats.transfer_end, NULL);

	if (debug > 0 || show_stats) {
		int64_t start = stats.transfer_start.tv_sec * 1000000 + stats.transfer_start.tv_usec;
		int64_t end = stats.transfer_end.tv_sec * 1000000 + stats.transfer_end.tv_usec;
		int64_t startup = stats.start.tv_sec * 1000000 + stats.start.tv_usec;
		long bps = (long) (stats.bytes / ((end - start) / 1000000.0));
		printf("%ld bytes transfered in %ldms (%.2lf KB/s) startup %ldms\n", stats.bytes, (end - start)/1000, bps/1024.0, (start-startup)/1000);
		printf("%ld packets received, %ld packets sent, %ld retransmissions\n", stats.packets_received, stats.packets_sent, stats.retransmits);
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////
// Main
/////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {

	int status;

	/* Option: Debug Level */
	if (argc > 1 && strncmp(argv[1], "--debug=",8) == 0) {
		debug = atoi(argv[1]+8);
		shift;
	}

	/* Option: Quiet Mode */
	if (argc > 1 && strncmp(argv[1], "-q",2) == 0) {
		show_stats = 0;
		shift;
	}

	/* Option: Payload Length*/
	if (argc > 1 && strncmp(argv[1], "--payload-len=",14) == 0) {
		payload_len = atoi(argv[1]+14);
		shift;
	}

	/* Check for server mode */
	if (argc > 1 && strcmp(argv[1], "--receive") == 0) {
		shift;
		return up_server(argc, argv);
	}

	/* Run client mode */
	return up_client(argc, argv);
}
