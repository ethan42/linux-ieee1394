# Base image to build targets
FROM debian:latest as builder

RUN apt update && apt install -fy gcc
COPY outbound_phy_packet_callback.c .
RUN gcc -o /outbound_phy_packet_callback outbound_phy_packet_callback.c
COPY packet_buffer_get.c .
RUN gcc -o /packet_buffer_get packet_buffer_get.c

# First target: the outbound physical packet callback
FROM debian:latest as outbound-phy-packet-callback

RUN apt update && apt install -fy libc6-dbg

COPY  --from=builder /outbound_phy_packet_callback /outbound_phy_packet_callback

ENTRYPOINT []
CMD ["/outbound_phy_packet_callback", "@@"]

# Second target: the packet buffer get callback
FROM debian:latest as packet-buffer-get

RUN apt update && apt install -fy libc6-dbg

COPY --from=builder /packet_buffer_get /packet_buffer_get

ENTRYPOINT []
CMD ["/packet_buffer_get", "@@"]
