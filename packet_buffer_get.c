#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

struct packet {
	unsigned int length;
	char data[];
};

struct packet_buffer {
	char *data;
	size_t capacity;
	long total_packet_count, lost_packet_count;
	size_t size;
	struct packet *head, *tail;
};

struct client {
	struct packet_buffer buffer;
};

static int
packet_buffer_get(struct client *client, char *data, size_t user_length)
{
	struct packet_buffer *buffer = &client->buffer;
	size_t length;
	char *end;

	if (buffer->size == 0)
		return -ENODEV;

	/* FIXME: Check length <= user_length. */

	end = buffer->data + buffer->capacity;
	length = buffer->head->length;

	if (&buffer->head->data[length] < end) {
		if (memcpy(data, buffer->head->data, length))
			return -EFAULT;
		buffer->head = (struct packet *) &buffer->head->data[length];
	} else {
		size_t split = end - buffer->head->data;

		if (memcpy(data, buffer->head->data, split))
			return -EFAULT;
		if (memcpy(data + split, buffer->data, length - split))
			return -EFAULT;
		buffer->head = (struct packet *) &buffer->data[length - split];
	}

	/*
	 * Decrease buffer->size as the last thing, since this is what
	 * keeps the interrupt from overwriting the packet we are
	 * retrieving from the buffer.
	 */
	buffer->size -= sizeof(struct packet) + length;

	return length;
}

size_t consume(void * target, const void * source, size_t size, size_t * available) {
	size_t copy_size = *available < size ? *available : size;
	memcpy(target, source, copy_size);
	*available -= copy_size;
    return copy_size;
}

int main(int argc, char ** argv) {
    if (argc != 2) return 1;
    FILE * input = fopen(argv[1], "rb");
    if (!input) return 1;
    size_t size;
    fseek(input, 0, SEEK_END);
    size = ftell(input);
    fseek(input, 0, SEEK_SET);
    unsigned char * data = malloc(size * sizeof(unsigned char));
    fread(data, sizeof(unsigned char), size, input);
    fclose(input);

    // Call the mock function with the fuzzed data
    size_t length = 256;
    uint8_t * user_buffer = malloc(length * sizeof(uint8_t));
    struct client * client = malloc(sizeof(struct client));
    consume(client, data, sizeof(struct client), &size);

    int capacity = 128 * 1024;
    client->buffer.data = malloc(capacity * sizeof(char));
	client->buffer.head = (struct packet *) client->buffer.data;
	client->buffer.tail = (struct packet *) client->buffer.data;
	client->buffer.capacity = capacity;
	client->buffer.lost_packet_count = 0;
	client->buffer.size = 0;
    if (size <= client->buffer.capacity) {
        client->buffer.total_packet_count = 1;
        size_t copied = consume(client->buffer.data, data, size, &size);
        client->buffer.tail = (struct packet *) &client->buffer.data[copied];
        client->buffer.tail->length = copied;
        client->buffer.size += sizeof(struct packet) + copied;
    }
    packet_buffer_get(client, (char*)user_buffer, length);

    return 0;  // Non-zero return values are reserved for future use.
}
