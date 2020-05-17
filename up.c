#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <errno.h> 
#include <string.h> 
#include <time.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
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

int payload_len = 1024;
int debug = 5;

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

#define PACKET_QUEUE_LIMIT 1000

void hex_dump(char *mem, int len) {
	int i, o = 0;
	while (len > 0) {
		printf("%08x", o);
		for (i = 0; i < 32 && len > 0; i++, len--) {
			printf(" %02x", *mem);
			mem++;
		}
		o += 32;
		printf("\n");
	}
}

// add packet to queue
packet_queue_t *add_packet_to_queue(packet_queue_t *this, packet_queue_t **head, long seq) {
	packet_queue_t *insert = *head;
	packet_queue_t *prev = 0;
	
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
			prev->next = this;
		} else {
			*head = this;
		}
	} else {
		// Append packet to list
		if (prev) {
			prev->next = this;
		} else {
			*head = this;
		}
	}

	return this;
}

packet_queue_t *remove_packet_from_queue(packet_queue_t **head, long seq) {
	packet_queue_t *entry = *head;
	packet_queue_t *prev = NULL;
	while (entry && entry->packet->seq != seq) {
		prev = entry;
		entry = entry->next;
	}
	if (entry) {
		if (prev) {
			prev->next = entry->next;
		} else {
			*head = entry->next;
		}
	}
	return entry;
}

packet_queue_t *find_packet_in_queue(packet_queue_t *entry, long seq) {
	while (entry && entry->packet->seq != seq) {
		entry = entry->next;
	}
	return entry;
}

///////////////////////////////////////////////////////////////////////////////////
// UP Server
///////////////////////////////////////////////////////////////////////////////////

// up --receive client-ip port
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
	int queued = 0;

	printf("SERVER\n");

	// Parse arguments
	shift;
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
	// addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_addr.s_addr = inet_addr(ip);

	// Bind listening socket
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind failed");
		return EXIT_FAILURE;
	}

	if (debug > 5) printf("SOCKET %x LISTENING ON %lx:%d\n", sockfd, (unsigned long)addr.sin_addr.s_addr, port);

	// Initialise client address
	memset(&caddr, 0, sizeof(struct sockaddr_in));
	caddr.sin_family = AF_INET;
	caddr.sin_port = htons(port);
	caddr.sin_addr.s_addr = inet_addr(ip);

	if (debug > 5) printf("CLIENT ADDR: %s:%d\n", ip, port);

	while (!eof) {
		if (debug > 8) printf("NOT DONE\n");

		// Drain packet queue if we already have the next sequence of packets
		while (packet_queue && packet_queue->packet->seq == seq_w) {
			if (debug > 5) printf("DRAIN QUEUE\n");

			// remove packet from the queue
			packet_queue_t *this = packet_queue;
			packet_queue = packet_queue->next;

			// TODO: Write packet to file
			seq_w++;
			if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", this->packet->type, this->packet->seq, this->packet->payload, this->packet->length);

			// Free packet
			free(this->packet);
			free(this);
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
		printf("RECV FROM %lx:%d...\n", (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
		if ((n = recvfrom(sockfd, packet, HEADER_LEN + payload_len, 0, (struct sockaddr *) &caddr, &len)) < 0) {

			perror("recvfrom");
			printf("n:%d errno:%d\n", n, errno);
			sleep(1);

		} else {

			if (debug > 5) {
				printf("SERVER RECV: type:%c seq:%ld len:%d PAYLOAD LENGTH %d FROM %lx:%d\n", packet->type, (long)packet->seq, n, packet->length, (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
				printf("PACKET SEQ %d SEQ_W %d\n", packet->seq, seq_w);
			}

			if (packet->seq == seq_w) {
				if (packet->type == 'E') {
					// EOF
					printf("EOF\n");
					eof = 1;
				} else {
					// write data to file
					if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", packet->type, packet->seq, packet->payload, packet->length);
					if (packet->length) {
						if (debug > 5) hex_dump(packet->payload, packet->length);
					}
				}
				seq_w ++;

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

			} else if (packet->seq > seq_w) {
				// only store packets not already written, to the queue, and only if room
				packet_queue_t *this = NULL;
				if (queued < PACKET_QUEUE_LIMIT && (this = malloc(sizeof (packet_queue_t)))) {

					this->ts = time(0);
					packet = this->packet = realloc(packet, HEADER_LEN + packet->length);
					this->retransmits = 0;

					this = add_packet_to_queue(this, &packet_queue, packet->seq);
					if (this) {
						queued++;
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
					nack.seq = packet->seq;
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
	char *remote;
	int sockfd;
	int port;
	int n;
	int len;
	packet_queue_t *packet_queue = NULL;
	int queued = 0;
	int eof = 0;

	// Parse arguments
	remote = shift;		// remote IP or user@host for ssh connection
	port = ishift;

	if (debug > 5) printf("CLIENT: REMOTE IS %s:%d\n", remote, port);

	// Open Socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket creation failed");
		return EXIT_FAILURE;
	}

	// Initialise send to address
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (!inet_aton(remote, &addr.sin_addr)) {
		perror("invalid address");
		return EXIT_FAILURE;
	}

	// Read standard input
	while (!eof || queued) {

		if (debug > 5) printf("eof:%d queued:%d\n", eof, queued);

		// As long as the packet queue is not full, read from standard input
		// and send to server, adding packet to packet queue
		if (!eof && queued < PACKET_QUEUE_LIMIT) {
			
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
				if (debug > 5) printf("READ %d BYTES FROM STDIN OFFSET %ld\n", n, offset);
				if (debug > 5) hex_dump(packet->payload, n);
				offset += n;
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
				this = add_packet_to_queue(this, &packet_queue, packet->seq);
				if (this) {
					queued++;
					if (debug > 8) printf("QUEUE ENTRY %p COUNT %d\n", this, queued);
					if (debug > 5) printf("CLIENT QUEUE PACKET [%p]: TYPE:%c SEQ:%ld LENGTH:%d\n", packet, packet->type, (long)packet->seq, packet->length);
				} else {
					perror("adding packet to queue");
					return EXIT_FAILURE;
				}

				// Send payload
				if (debug > 0) printf("SEND PACKET [%p]: TYPE:%c SEQ:%ld LENGTH:%d TO %lx:%d\n", packet, packet->type, (long)packet->seq, packet->length, (unsigned long)addr.sin_addr.s_addr, ntohs(addr.sin_port));
				sendto(sockfd, packet, HEADER_LEN + n, 0, (struct sockaddr *) &addr, sizeof(addr));
				if (debug > 5) printf("SEND DONE\n");

				// We gave the packet to the packet queue
				packet = NULL;
			} else {
				perror("reading standard input");
				return EXIT_FAILURE;
			}
		}

		if (queued) {

			if (debug > 5) printf("PROCESS QUEUE [SIZE:%d]\n", queued);

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

				// Process packet
				switch(packet->type) {
				case 'A': // handle ack 
					{
						packet_queue_t *removed = remove_packet_from_queue(&packet_queue, packet->seq);
						if (removed) {
							queued--;
							if (debug > 5) printf("REMOVED ACKED PACKET [%d]: TYPE:%c SEQ:%ld LENGTH:%d\n", queued, removed->packet->type, (long)removed->packet->seq, removed->packet->length);
							free(removed->packet);
							free(removed);
						}
					}
					break;
				case 'N': // handle nack
					{
						packet_queue_t *entry = find_packet_in_queue(packet_queue, packet->seq);
						if (entry) {
							// resend this packet
							if (debug > 5) printf("RESEND NACKED PACKET [%d]: TYPE:%c SEQ:%ld LENGTH:%d\n", queued, entry->packet->type, (long)entry->packet->seq, entry->packet->length);
							sendto(sockfd, entry->packet, HEADER_LEN + entry->packet->length, 0, (struct sockaddr *) &addr, sizeof(addr));
							entry->retransmits++;
						}
					}
					break;
				}
			}
		}
	}

	if (n < 0) {
		perror("read");
		return EXIT_FAILURE;
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////////////////
// Main
/////////////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "--receive") == 0) return up_server(argc--, argv++);
	return up_client(argc, argv);
}
