static void outbound_phy_packet_callback(struct fw_packet *packet,
					 struct fw_card *card, int status)
{
	struct outbound_phy_packet_event *e =
		container_of(packet, struct outbound_phy_packet_event, p);

	switch (status) {
	/* expected: */
	case ACK_COMPLETE:	e->phy_packet.rcode = RCODE_COMPLETE;	break;
	/* should never happen with PHY packets: */
	case ACK_PENDING:	e->phy_packet.rcode = RCODE_COMPLETE;	break;
	case ACK_BUSY_X:
	case ACK_BUSY_A:
	case ACK_BUSY_B:	e->phy_packet.rcode = RCODE_BUSY;	break;
	case ACK_DATA_ERROR:	e->phy_packet.rcode = RCODE_DATA_ERROR;	break;
	case ACK_TYPE_ERROR:	e->phy_packet.rcode = RCODE_TYPE_ERROR;	break;
	/* stale generation; cancelled; on certain controllers: no ack */
	default:		e->phy_packet.rcode = status;		break;
	}
	e->phy_packet.data[0] = packet->timestamp;

	queue_event(e->client, &e->event, &e->phy_packet,
		    sizeof(e->phy_packet) + e->phy_packet.length, NULL, 0);
	client_put(e->client);
}