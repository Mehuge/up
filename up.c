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

#define SYN_PACKET 'S'
#define PAY_PACKET 'P'
#define ACK_PACKET 'A'
#define NAK_PACKET 'N'
#define EOF_PACKET     'E'
#define FIN_PACKET 'F'

int payload_len = 1400;
int debug = 1;
int show_stats = 1;

struct packet {
  char type;
  char reserved[3];
  uint32_t seq;
  uint16_t length;
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
  long start;
  long transfer_start;
  long transfer_end;
  long reads;
  long bytes;
  long packets_sent;
  long packets_received;
  long retransmits;
	long sleeping;
};

typedef struct stats stats_t;

int CLIENT_PACKET_QUEUE_LIMIT = 50;
int SERVER_PACKET_QUEUE_LIMIT = 1000;
int SERVER_NACK_THRESHOLD = 5;

long nowms() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

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
}

// add packet to queue, in sequence order
// TODO: We only add packets in order, so the more packets are added the more traversal
// we need to do, if we knew where the last one was, we could append easily.
packet_queue_t *insert_packet_in_queue(packet_queue_t *this, packet_queue_t **head, packet_queue_t **tail, long seq) {
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
      if (debug > 4) printf("INSERT AFTER: PREV %p\n",prev),fflush(stdout);
      prev->next = this;  // insert after previous
    } else {
      if (debug > 4) printf("INSERT AT TOP\n"),fflush(stdout);
      *head = this;    // insert at top of list
    }
  } else {
    // Append packet to possibly empty list
    if (prev) {
      if (debug > 4) printf("APPEND PACKET: PREV %p\n",prev),fflush(stdout);
      *tail = prev->next = this;  // prev is last entry
    } else {
      if (debug > 4) printf("EMPTY LIST: PREV IS NULL\n"),fflush(stdout);
      *tail = *head = this;    // was empty list
    }
  }

  return this;
}

// add packet to end of queue.                                                                                      
packet_queue_t *append_packet_to_queue(packet_queue_t *this, packet_queue_t **head, packet_queue_t **tail, long seq) { 
  if (debug > 4) printf("APPEND_PACKET\n"),fflush(stdout);
  this->next = NULL;
  return *head ? (*tail = (*tail)->next = this) : (*tail = *head = this);
}

void dump_queue(packet_queue_t *head, packet_queue_t *tail, int queued) {
  printf(" PACKET QUEUE LENGTH %d HEAD %p TAIL %p\n", queued, head, tail),fflush(stdout);
  packet_queue_t *entry = head;
  while (entry) {
    printf("  ENTRY %11p NEXT %11p PACKET %11p TYPE %c SEQ %ld LENGTH %4d PAYLOAD %11p\n",
			entry, entry->next, entry->packet, entry->packet->type,
			(long)entry->packet->seq, entry->packet->length, entry->packet->payload
		);
		fflush(stdout);
    entry = entry->next;
  }
}

// Remove acked packet. Note: If we receive an ACK for seq 10, we know the
// server has accepted and acknowledged all packets up to and including 10
// even though we may not have received the ack, so we treat any packet whos
// sequense is less than or equal to this ack, as acknowledged, and remove it
// from the list.
void remove_acked_packets_from_queue(packet_queue_t **head, packet_queue_t **tail, long seq, int *queued) {
  if (debug > 9) printf("REMOVE_ACKED_PACKETS\n"),fflush(stdout);
  packet_queue_t *entry = *head;
  packet_queue_t *prev = NULL;
  while (entry) {
    if (debug > 99) printf("ENTRY %p SEQ %ld ACK %ld\n", entry, (long)entry->packet->seq, seq);
    if (entry->packet->seq <= seq) {
      packet_queue_t *e = entry;
      if (debug > 10) dump_queue(*head, *tail, *queued);
      if (debug > 5) printf("REMOVE %p ACKED PACKET %p: TYPE:%c SEQ:%ld LENGTH:%d\n", entry, entry->packet, entry->packet->type, (long)entry->packet->seq, entry->packet->length);
      if (debug > 99) printf("PREV %p HEAD %p TAIL %p NEXT %p\n", prev, *head, *tail, entry->next);
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
      if (debug > 10) dump_queue(*head, *tail, *queued);
    } else {
      prev = entry;
      entry = entry->next;
    }
  }
}

packet_queue_t *find_packet_in_queue(packet_queue_t *entry, long seq) {
  while (entry && entry->packet->seq != seq) {
    entry = entry->next;
  }
  return entry;
}

// PROTOCOL: {{
//
//   NACK:
//     Packet Type: N
//     Sequence: <expected sequence>
//     Payload Length: 4
//     Payload:
//       Have Sequence: <lowest queued sequence>
//
//	A nack tells the client the sequence the server was expecting, and also the sequence of
//	the first packet (lowest sequence) currently being held in a queue by the server. The 
//	range defined by this indicates the range of probable lost packets, which the client
//	can then resend.
//
// }}

int send_nack(int sockfd, uint32_t want_seq, uint32_t have_seq, struct sockaddr_in *addr) {
	packet_t nack;
	nack.type = 'N';
	nack.reserved[0] = nack.reserved[1] = nack.reserved[2] = 0;
	nack.seq = htonl(want_seq);
	*((uint32_t *)nack.payload) = htonl(have_seq);
	nack.length = sizeof(uint32_t);
	if (debug > 5) printf("SEND %c SEQ:%ld HAVE:%ld LENGTH:%d TO %lx:%d\n", nack.type,
		(long)want_seq, (long)have_seq, HEADER_LEN + nack.length, (unsigned long)addr->sin_addr.s_addr, ntohs(addr->sin_port)
	), fflush(stdout);
	return sendto(sockfd, &nack, HEADER_LEN + nack.length, 0, (struct sockaddr *) addr, sizeof(*addr));
}

// PROTOCOL: {{
//
//   NACK:
//     Packet Type: N
//     Sequence: <expected sequence>
//     Payload Length: 4
//     Payload:
//       Have Sequence: <lowest queued sequence>
//
//	An ack tells the client the sequence the server has processed (received and written)
//	the packet for this sequence. The client can assume that all packets up to and including
//	that sequence have been successfully processed by the server. Indeed the server may not
//	send an ack for every packet.
//
//	The server will only ever ack a packet that has been received and written in the correct
//	order, therefore all packets with sequences lower than the ack sequence must also have been
//	successfully processed by the server
//
// }}

int send_ack(int sockfd, uint32_t got_seq, struct sockaddr_in *addr) {
	packet_t ack;
	ack.type = ACK_PACKET;
	ack.reserved[0] = ack.reserved[1] = ack.reserved[2] = 0;
	ack.seq = htonl(got_seq);
	if (debug > 5) printf("SEND %c SEQ:%ld LENGTH:%d TO %lx:%d\n", ack.type, (long)got_seq, OFFSETOF(ack,length), (unsigned long)addr->sin_addr.s_addr, ntohs(addr->sin_port)),fflush(stdout);
	return sendto(sockfd, &ack, OFFSETOF(ack,length), 0, (struct sockaddr *)addr, sizeof(*addr));
}

// PROTOCOL: {{
// }}

int send_syn(int sockfd, struct sockaddr_in *addr) {
	packet_t syn;
  syn.type = SYN_PACKET;
  if (debug > 5) printf("SEND %c LENGTH:%d TO %lx:%d\n", syn.type, OFFSETOF(syn,reserved), (unsigned long)addr->sin_addr.s_addr, ntohs(addr->sin_port)),fflush(stdout);
  return sendto(sockfd, &syn, OFFSETOF(syn,reserved), 0, (struct sockaddr *) addr, sizeof(*addr));
}

int send_fin(int sockfd, struct sockaddr_in *addr) {
	packet_t fin;
  fin.type = FIN_PACKET;
  if (debug > 5) printf("SEND %c LENGTH:%d TO %lx:%d\n", fin.type, OFFSETOF(fin,reserved), (unsigned long)addr->sin_addr.s_addr, ntohs(addr->sin_port)),fflush(stdout);
  return sendto(sockfd, &fin, OFFSETOF(fin,reserved), 0, (struct sockaddr *) addr, sizeof(*addr));
}

// The packet fields seq and length are sent over the wire in network byte order
// these routines will convert the packet to and from network byte order, and should
// be called around a sendto() call.

void hton_packet(packet_t *packet) {
	packet->seq = htonl(packet->seq);
	packet->length = htons(packet->length);
}

void ntoh_packet(packet_t *packet) {
	packet->seq = ntohl(packet->seq);
	packet->length = ntohs(packet->length);
}

///////////////////////////////////////////////////////////////////////////////////
// UP Server
///////////////////////////////////////////////////////////////////////////////////

// up --receive server-ip port [client-ip]
int up_server(int argc, char **argv) {
  struct sockaddr_in addr, caddr;
  long want_seq = 0;								// PROTOCOL: The next packet sequence we are expecting
	long last_nack = 0;								// PROTOCOL: Time the last nack was sent
  char *ip;
  int port;
  socklen_t len;
  int n;
  int sockfd;
  long eof = 0;
	long fin = 0;
	long ms;
	long took;
	int sav_errno;
  packet_t *packet = NULL;
	stats_t stats;

  packet_queue_t *packet_queue = NULL;
  packet_queue_t *queue_tail = NULL;
  int queued = 0;

  // Parse arguments
  ip = shift;
  port = ishift;

	// Initialise stats
  memset(&stats, 0, sizeof(stats));
  stats.start = nowms();

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

  if (debug > 5) printf("SOCKET %x LISTENING ON %lx:%d\n", sockfd, (unsigned long)addr.sin_addr.s_addr, port),fflush(stdout);

  // Initialise client address (we don't know it yet)
  memset(&caddr, 0, sizeof(struct sockaddr_in));
  caddr.sin_family = AF_INET;
  caddr.sin_port = htons(port);
  caddr.sin_addr.s_addr = INADDR_ANY;

  while (!fin) {
		long ack_seq = -1;

    if (debug > 8 && packet_queue) printf("- TICK - PACKET_QUEUE %p SEQ_W %ld QUEUED PACKET SEQ %ld\n", packet_queue, want_seq, (long)packet_queue->packet->seq),fflush(stdout);

    // Drain packet queue if we already have the next sequence of packets
    while (packet_queue && packet_queue->packet->seq == want_seq) {
      if (debug > 5) printf("DRAIN QUEUE\n"),fflush(stdout);

      // remove packet from the queue
      packet_queue_t *this = packet_queue;
      packet_queue = packet_queue->next;
      if (!packet_queue) queue_tail = NULL;
      queued --;

      // TODO: Write packet to file

			// Track which packet to ack.
			ack_seq = want_seq;
      want_seq++;
			if (this->packet->type == EOF_PACKET) {
				eof = nowms();
        if (debug > 0) printf("EOF\n"),fflush(stdout);
			} else {
				if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", this->packet->type, this->packet->seq, this->packet->payload, this->packet->length),fflush(stdout);
			}

      // Free packet
      free(this->packet);
      free(this);

      if (debug > 10) dump_queue(packet_queue, queue_tail, queued),fflush(stdout);
    }

		// We drained the queue, need to ack the last packet drained
		if (ack_seq > -1) {
			if (debug > 4) printf("SEND DRAIN QUEUE ACK %ld\n", ack_seq);
			send_ack(sockfd, ack_seq, &caddr);
		}

    // Allocate a packet buffer if needed
    if (!packet) {
      if ((packet = malloc(HEADER_LEN + payload_len)) == NULL) {
        perror("allocating payload buffer");
        return EXIT_FAILURE;
      }
      if (debug > 18) printf("ALLOCATED BUFFER %p LENGTH %d\n", packet, HEADER_LEN + payload_len),fflush(stdout);
    }

    len = sizeof(caddr);
    if (debug > 5) printf("(%ld) RECV FROM %lx:%d...\n", nowms(), (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port)),fflush(stdout);
		ms = nowms();
    n = recvfrom(sockfd, packet, HEADER_LEN + payload_len, queued ? MSG_DONTWAIT : 0, (struct sockaddr *) &caddr, &len);
		sav_errno = errno;
		took = nowms() - ms;
	
		if (n < 0 && sav_errno != EAGAIN) {
			errno = sav_errno;
			perror("recvfrom");
			printf("n:%d errno:%d\n", n, errno),fflush(stdout);
			sleep(1);
		}

		// PROTOCOL: {{
		//   
		// }}
		
		else if (n < 0) {

			if (last_nack > 0 && (nowms() - last_nack > 1000)) {
				if (debug > 5) printf("RESEND NACK FOR SEQ %ld QUEUED %d LAST_NACK %ld\n", want_seq, queued, last_nack);
				send_nack(sockfd, want_seq, packet_queue->packet->seq, &caddr);
				last_nack = nowms();
			} else {
				if (debug > 0) printf("NO DATA - WAIT 100us\n"),fflush(stdout);
				usleep(100);
				stats.sleeping += 100;
			}
    } 

		// PROTOCOL: {{
		//   
		// }}
		
		else if (n == 0) {
			printf("DO WE EVER SEE THIS? WAIT 1ms");
			usleep(1000);
			stats.sleeping += 1000;
		}

		else {

			packet->seq = ntohl(packet->seq);
			if (n >= HEADER_LEN) packet->length = ntohs(packet->length);

      if (debug > 5) {
        printf("SERVER RECV: type:%c seq:%ld len:%d PAYLOAD LENGTH %d FROM %lx:%d\n", packet->type, (long)packet->seq, n, packet->length, (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port)),fflush(stdout);
        printf("PACKET SEQ %ld SEQ_W %ld\n", (long)packet->seq, want_seq),fflush(stdout);
      }

			// PROTOCOL: {{
			//
			// 	 If the client sends a S(tart) packet, respond with a S(tart) packet.
			//   The client does this so that it knows the server is ready to start receiving
			//   the data, otherwise the data will be lost and would need resending.
			//
			//   It is not a requirement of the protocol for the client to send a start
			//   packet, if the client knows the server is ready it can just start sending
			//   packets.
			//
			// }}
      if (packet->type == SYN_PACKET) {      // client sent SYN
				send_syn(sockfd, &caddr);
      }

			// PROTOCOL: {{
			//   The client sends a FIN after receiving the ACK packet for the EOF packet.
			// }}
			else if (packet->type == FIN_PACKET) {
				fin = nowms();
				send_fin(sockfd, &caddr);
			}

			// PROTOCOL: {{
			//
			//   If the sequence of the packet just received is the sequence we were expecting, then
			//   if the packet type was E(of) then we signal end of file (transfer) otherwisde we 
			//   write the data to the output stream. 
			//
			//   In either case, we A(ck) the packet.
			//
			// }}
      else if (packet->seq == want_seq) {
        if (packet->type == EOF_PACKET) {
          // EOF
          if (debug > 0) printf("EOF\n"),fflush(stdout);
          eof = nowms();
        } else {
          // write data to output stream
          if (debug > 0) printf("WRITE: TYPE:%c SEQ:%d, BUFFER:%p LENGTH:%d\n", packet->type, packet->seq, packet->payload, packet->length),fflush(stdout);
          if (packet->length) {
            if (debug > 5) hex_dump(packet->payload, packet->length),fflush(stdout);
          }
        }
        want_seq++;
				last_nack = 0;

        // Ack this packet
        send_ack(sockfd, packet->seq, &caddr);
      }

			// PROTOCOL: {{
			//
			//   If the sequence of the packet receivied is greater than the sequence we were expecting
			//   that means either that the packets are out of order, or that a packet was lost. In order
			//   to avoid N(acking) an out of order packet, only N(ack) the missing sequence once the
			//   queued packets list reaches a threshold.
			//
			// }}
      else if (packet->seq > want_seq) {
        packet_queue_t *this = NULL;

				if (debug > 0) printf("OUT OF ORDER PACKET: SEQ %ld SEQ_W %ld QUEUED %d\n", (long)packet->seq, want_seq, queued),fflush(stdout);

        // Drop packets once the queue reaches the server queue limit, or we run out of memory.
        if (queued < SERVER_PACKET_QUEUE_LIMIT && (this = malloc(sizeof (packet_queue_t)))) {

					if (debug > 0) printf("ADD PACKET TO QUEUE\n"),fflush(stdout);

          this->ts = time(0);
          packet = this->packet = realloc(packet, HEADER_LEN + packet->length);
          this->retransmits = 0;

          this = insert_packet_in_queue(this, &packet_queue, &queue_tail, packet->seq);
          if (this) {
            queued++;
            if (debug > 10) dump_queue(packet_queue, queue_tail, queued),fflush(stdout);
            if (debug > 5) printf("SERVER QUEUE PACKET [%d]: TYPE:%c seq:%ld len:%d FROM %lx:%d\n", queued, packet->type, (long)packet->seq, n, (unsigned long)caddr.sin_addr.s_addr, ntohs(caddr.sin_port)),fflush(stdout);
          }

          packet = NULL;
          if (debug > 5) printf("SET PACKET NULL\n");
        } else {
					if (debug > 0) printf("DROP PACKET\n"),fflush(stdout);
          // drop packet, queue full
          // TODO: Note, atm this drops the just received packet, but should it
          // drop the highest sequence packet instead?
        }

        // NAK packet sequence not received
        if (queued == SERVER_NACK_THRESHOLD || (last_nack > 0 && nowms() - last_nack > 1000)) {
          if (debug > 5) printf("SEND NACK FOR SEQ %ld QUEUED %d LAST_NACK %ld AGE %ld\n", want_seq, queued, last_nack, (nowms() - last_nack));
					send_nack(sockfd, want_seq, packet_queue->packet->seq, &caddr);
					last_nack = nowms();
        }
      }

			// PROTOCOL: {{
			//
			//   If n we receive a packet we have already processed then it is because the
			//   client never got the A(ck) for it, so resend the A(ck).
			//
			// }}
			else {
        // ACK old packets (to tell client to stop sending them)
				if (debug > 0) printf("SERVER RESEND ACK: FOR SEQ:%ld\n", (long)packet->seq);
				send_ack(sockfd, packet->seq, &caddr);
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
	long throttle = 0;

  // Initialise statistics
  memset(&stats, 0, sizeof(stats));
  stats.start = nowms();

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

  // Protocol loops runs while we have input, or there are queued (unacked) packets.
  while (!eof || queued) {

		if (throttle > 0) {
			printf("USLEEP %ld\n", throttle);
			usleep(throttle);
			stats.sleeping += throttle;
		}

    if (debug > 4) printf("-- eof:%d queued:%d starting:%d\n", eof, queued, starting);

		// PROTOCOL: {{
		// 	 If starting, send a SYN packet to the server. The server will respond by 
		// 	 sending a SYN as an acknowledgement when it is ready.
		// }}
    if (starting) {
			send_syn(sockfd, &addr);
      stats.packets_sent++;
    }

    // As long as the packet queue is not full, read from standard input
    // and send to server, adding the packet to packet queue
    if (!starting && !eof && queued < CLIENT_PACKET_QUEUE_LIMIT) {
      
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
        if (debug > 14) hex_dump(packet->payload, n),fflush(stdout);
        stats.bytes += n;
        if (n == 0) eof = 1;

        packet->type = eof ? EOF_PACKET : PAY_PACKET;
        packet->seq = seq++;
        packet->length = n;
        if (debug > 5) printf("CLIENT WILL SEND: SEQ:%ld LENGTH:%d\n", (long)packet->seq, packet->length);

        // Add packet to waiting for ack queue
        if (debug > 18) printf("ALLOCATE QUEUE ENTRY\n");
        packet_queue_t *this = malloc(sizeof(packet_queue_t));
        this->ts = time(0);
        if (debug > 18) printf("REALLOCATE QUEUED PACKET %p TO LENGTH %d\n", packet, HEADER_LEN + packet->length);
        packet = this->packet = realloc(packet, HEADER_LEN + packet->length);
        if (debug > 18) printf("DONE REALLOCATE: NEW PACKET %p\n", packet);
        this->retransmits = 0;

        if (debug > 8) printf("ADD PACKET TO QUEUE %p\n", this);
        this = append_packet_to_queue(this, &packet_queue, &queue_tail, packet->seq);
        if (this) {
          queued++;
          if (debug > 10) dump_queue(packet_queue, queue_tail, queued);
          if (debug > 8) printf("QUEUE ENTRY %p COUNT %d\n", this, queued);
          if (debug > 5) printf("QUEUE PACKET [%p]: TYPE:%c SEQ:%ld LENGTH:%d\n", packet, packet->type, (long)packet->seq, packet->length);
        } else {
          perror("adding packet to queue");
          return EXIT_FAILURE;
        }

        // Send payload
        if (debug > 5) printf("SEND %c SEQ:%ld LENGTH:%d TO %lx:%d\n", packet->type, (long)packet->seq, packet->length, (unsigned long)addr.sin_addr.s_addr, ntohs(addr.sin_port));
				hton_packet(packet);
        sendto(sockfd, packet, HEADER_LEN + n, 0, (struct sockaddr *) &addr, sizeof(addr));
				ntoh_packet(packet);
        stats.packets_sent++;

        // We gave the packet to the packet queue
        packet = NULL;
      } else {
        perror("reading standard input");
        return EXIT_FAILURE;
      }
    }

    if (queued || starting) {

      // Allocate a packet buffer
      if (!packet) {
        if ((packet = malloc(HEADER_LEN + payload_len)) == NULL) {
          perror("allocating payload buffer");
          return EXIT_FAILURE;
        }
        if (debug > 18) printf("ALLOCATED PACKET BUFFER: %p LENGTH %d\n", packet, HEADER_LEN + payload_len);
      }

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
				// Convert integers from network
				packet->seq = ntohl(packet->seq);
				if (n >= HEADER_LEN) packet->length = ntohs(packet->length);

        if (debug > 5) printf("RECV %c SEQ:%ld LEN:%d LENGTH:%d\n", packet->type, (long)packet->seq, n, n >= 12 ? packet->length : 0);
        stats.packets_received++;

        // Process packet
        switch(packet->type) {
        case ACK_PACKET: // handle ack 
          remove_acked_packets_from_queue(&packet_queue, &queue_tail, packet->seq, &queued);
					if (eof && queued == 0) {
						// If we just got an ack for the EOF, then we know the server
						// has written all data, and we can exit, tell the server to
						// exit by sending a FIN.
						send_fin(sockfd, &addr);
					}
          break;
				case FIN_PACKET:
					// ignore FIN
					break;
        case SYN_PACKET: // server has started
					if (starting) {
						starting = 0;
						stats.transfer_start = nowms();
						stats.sleeping = 0;
					}
          break;
        case NAK_PACKET: // handle nack
          {
						uint32_t got_seq = ntohl(*((long *)packet->payload));
						if (debug > 0) printf("GOT NACK FOR SEQ %ld:%ld\n", (long)packet->seq, (long)got_seq);
						if (debug > 10) dump_queue(packet_queue, queue_tail, queued);
						while (packet->seq < got_seq) {
							packet_queue_t *entry = find_packet_in_queue(packet_queue, packet->seq);
							if (entry) {
								// resend this packet
								long paylen = entry->packet->length;
								if (debug > 0) printf("RESEND NACKED PACKET %p TYPE:%c SEQ:%ld LENGTH:%d\n", entry->packet, entry->packet->type, (long)entry->packet->seq, entry->packet->length);
								hton_packet(entry->packet);
								sendto(sockfd, entry->packet, HEADER_LEN + paylen, 0, (struct sockaddr *) &addr, sizeof(addr));
								ntoh_packet(entry->packet);
								stats.packets_sent++;
								stats.retransmits++;
								entry->retransmits++;
							} else {
								perror("missing packet");
								return EXIT_FAILURE;
							}
							packet->seq ++;
            }
						throttle = throttle ? throttle * 2 : 8;
						printf("THROTTLE %ld\n", throttle);
          }
          break;
        }
      } else {
				long delay = 0;
        if (starting) {
					delay = 10 * starting * 1000;
          if (starting < 100) starting *= 2;
        }
				if (delay) {
					if (debug > 8) printf("NO RESPONSE sleep %ldus\n", delay);
					usleep(delay);
					stats.sleeping += delay;
				}
      }
    }
  }

  if (n < 0) {
    perror("read");
    return EXIT_FAILURE;
  }

  stats.transfer_end = nowms();

  if (debug > 0 || show_stats) {
    long start = stats.transfer_start;
    long end = stats.transfer_end;
    long startup = stats.start;
    long bps = (long) (stats.bytes / ((end - start) / 1000.0));
    printf("%ld bytes transfered in %ldms (%.2lf KB/s) startup %ldms\n", stats.bytes, (end - start), bps/1024.0, (start-startup)/1000);
    printf("%ld packets received, %ld packets sent, %ld retransmissions %ldus waiting\n", stats.packets_received, stats.packets_sent, stats.retransmits, stats.sleeping);
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

  /* Option: Payload Length*/
  if (argc > 1 && strncmp(argv[1], "--queue-max=",12) == 0) {
    CLIENT_PACKET_QUEUE_LIMIT = atoi(argv[1]+12);
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
