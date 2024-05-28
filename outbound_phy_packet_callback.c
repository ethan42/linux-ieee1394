#include <string.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;

// Assuming standard Linux types for FireWire communication
struct fw_packet {
    // Placeholder members
    u32 timestamp; // Example field
};

struct fw_card {
    // Placeholder members
    int dummy;
};

enum ack_status {
    ACK_COMPLETE,
    ACK_PENDING,
    ACK_BUSY_X,
    ACK_BUSY_A,
    ACK_BUSY_B,
    ACK_DATA_ERROR,
    ACK_TYPE_ERROR
};

enum rcode_status {
    RCODE_COMPLETE,
    RCODE_BUSY,
    RCODE_DATA_ERROR,
    RCODE_TYPE_ERROR
};

// Event types
enum {
    FW_CDEV_EVENT_PHY_PACKET_SENT,
    FW_CDEV_EVENT_PHY_PACKET_SENT2
};

struct fw_cdev_event_phy_packet {
	u32 type;
    u32 rcode;
    u8 data[0]; // Flexible array member for data
    u32 length; // Size of the data
};

struct fw_cdev_event_phy_packet2 {
    u32 rcode;
    u64 tstamp; // Extended timestamp
    u32 length; // Size of the data
};

// Your custom types
struct outbound_phy_packet_event {
    struct fw_packet p;
    struct client *client;
    union {
        struct fw_cdev_event_phy_packet without_tstamp;
        struct fw_cdev_event_phy_packet2 with_tstamp;
    } phy_packet;
    // Placeholder for event data
    int event;
};

struct client {
    // Placeholder members
	u32 in_shutdown;
	int kref;
};

// Placeholder for container_of macro, usually provided by the kernel
#define container_of(ptr, type, member) ({          \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})

// Simulated function to queue an event
void queue_event(struct client *client, int *event, void *event_data, size_t data_size, void *unused1, int unused2) {
	if (client->in_shutdown) {
		struct outbound_phy_packet_event *e = container_of(event, struct outbound_phy_packet_event, event);
		free(e);
	}
}

// Simulated function to decrease the client's reference count
int client_put(struct client *client) {
    client->kref --;
	return 0;
}

// Warning function, typically used in kernel code for unexpected conditions
void WARN_ON(int condition) {
    // Placeholder for functionality
}

static void outbound_phy_packet_callback(struct fw_packet *packet,
					 struct fw_card *card, int status)
{
	struct outbound_phy_packet_event *e =
		container_of(packet, struct outbound_phy_packet_event, p);
	struct client *e_client = e->client;
	u32 rcode;

	switch (status) {
	// expected:
	case ACK_COMPLETE:
		rcode = RCODE_COMPLETE;
		break;
	// should never happen with PHY packets:
	case ACK_PENDING:
		rcode = RCODE_COMPLETE;
		break;
	case ACK_BUSY_X:
	case ACK_BUSY_A:
	case ACK_BUSY_B:
		rcode = RCODE_BUSY;
		break;
	case ACK_DATA_ERROR:
		rcode = RCODE_DATA_ERROR;
		break;
	case ACK_TYPE_ERROR:
		rcode = RCODE_TYPE_ERROR;
		break;
	// stale generation; cancelled; on certain controllers: no ack
	default:
		rcode = status;
		break;
	}

	switch (e->phy_packet.without_tstamp.type) {
	case FW_CDEV_EVENT_PHY_PACKET_SENT:
	{
		struct fw_cdev_event_phy_packet *pp = &e->phy_packet.without_tstamp;

		pp->rcode = rcode;
		pp->data[0] = packet->timestamp;
		queue_event(e->client, &e->event, &e->phy_packet, sizeof(*pp) + pp->length,
			    NULL, 0);
		break;
	}
	case FW_CDEV_EVENT_PHY_PACKET_SENT2:
	{
		struct fw_cdev_event_phy_packet2 *pp = &e->phy_packet.with_tstamp;

		pp->rcode = rcode;
		pp->tstamp = packet->timestamp;
		queue_event(e->client, &e->event, &e->phy_packet, sizeof(*pp) + pp->length,
			    NULL, 0);
		break;
	}
	default:
		WARN_ON(1);
		break;
	}

	// client_put(e->client);
	client_put(e_client);
}

void consume(void * target, const void * source, size_t size, size_t * available) {
	size_t copy_size = *available < size ? *available : size;
	memcpy(target, source, copy_size);
	*available -= copy_size;
}

void firewire_read_mock(uint8_t *data, size_t size) {

	int status;
	// initialize the status variable
	consume(&status, data, sizeof(status), &size);

	// initialize the client
	struct client * client = malloc(sizeof(struct client));
	consume(client, data, sizeof(struct client), &size);

	// initialize the event
	struct outbound_phy_packet_event * event = malloc(sizeof(struct outbound_phy_packet_event));
	consume(event, data, sizeof(struct outbound_phy_packet_event), &size);
	event->client = client;

	// call the function we want to fuzz
	outbound_phy_packet_callback(&event->p, NULL, status);
}

int main(int argc, char ** argv) {
	if (argc != 2) return 1;
	FILE * packet = fopen(argv[1], "rb");
	if (!packet) return 1;
	size_t size;
	fseek(packet, 0, SEEK_END);
	size = ftell(packet);
	rewind(packet);
	uint8_t * data = malloc(size);
	fread(data, 1, size, packet);
	firewire_read_mock(data, size);
	free(data);
	fclose(packet);
}
