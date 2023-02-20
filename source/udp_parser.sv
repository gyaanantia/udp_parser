module udp_parser #(
    parameter PCAP_HEADER_BYTES      = 24,
    parameter PCAP_DATA_HEADER_BYTES = 16,
    parameter ETH_DST_ADDR_BYTES     = 6,
    parameter ETH_SRC_ADDR_BYTES     = 6,
    parameter ETH_PROTOCOL_BYTES     = 2,
    parameter IP_VERSION_BYTES       = 1,
    parameter IP_HEADER_BYTES        = 1,
    parameter IP_TYPE_BYTES          = 1,
    parameter IP_LENGTH_BYTES        = 2,
    parameter IP_ID_BYTES            = 2,
    parameter IP_FLAG_BYTES          = 2,
    parameter IP_TIME_BYTES          = 1,
    parameter IP_PROTOCOL_BYTES      = 1,
    parameter IP_CHECKSUM_BYTES      = 2,
    parameter IP_SRC_ADDR_BYTES      = 4,
    parameter IP_DST_ADDR_BYTES      = 4,
    parameter UDP_DST_PORT_BYTES     = 2,
    parameter UDP_SRC_PORT_BYTES     = 2,
    parameter UDP_LENGTH_BYTES       = 2,
    parameter UDP_CHECKSUM_BYTES     = 2,
    parameter IP_PROTOCOL_DEF        = 16'h0800,
    parameter IP_VERSION_DEF         = 4'h4,
    parameter UDP_PROTOCOL_DEF       = 8'h11,
    parameter DATA_WIDTH             = 8
)
(
    input  logic                    clock,
    input  logic                    reset,
    input  logic                    in_sof,
    input  logic                    in_eof,
    input  logic [DATA_WIDTH-1:0]   din,
    input  logic                    empty,
    output logic                    in_rd_en,
    output logic [DATA_WIDTH-1:0]   dout
);

typedef enum logic [4:0] { wait_for_sof, eth_dst_addr_state, eth_src_addr_state, eth_protocol_state, ip_version_header_state, ip_type_state, ip_length_state, ip_id_state, ip_flag_state, ip_time_state, ip_protocol_state, ip_checksum_state, ip_src_addr_state, ip_dst_addr_state, udp_dst_port_state, udp_src_port_state, udp_length_state, udp_checksum_state } state_t;
state_t state, state_c;

integer num_bytes, num_bytes_c;
logic [(ETH_DST_ADDR_BYTES*8)-1:0] eth_dst_addr, eth_dst_addr_c;
logic [(ETH_SRC_ADDR_BYTES*8)-1:0] eth_src_addr, eth_src_addr_c;
logic [(ETH_PROTOCOL_BYTES*8)-1:0] eth_procotol, eth_protocol_c;
logic [(IP_VERSION_BYTES*4)-1:0] ip_version, ip_version_c;
logic [(IP_HEADER_BYTES*4)-1:0] ip_header, ip_header_c;
logic [(IP_TYPE_BYTES*8)-1:0] ip_type, ip_type_c;
logic [(IP_LENGTH_BYTES*8)-1:0] ip_length, ip_length_c;
logic [(IP_ID_BYTES*8)-1:0] ip_id, ip_id_c;
logic [(IP_FLAG_BYTES*8)-1:0] ip_flag, ip_flag_c;
logic [(IP_TIME_BYTES*8)-1:0] ip_time, ip_time_c;
logic [(IP_PROTOCOL_BYTES*8)-1:0] ip_protocol, ip_protocol_c;
logic [(IP_CHECKSUM_BYTES*8)-1:0] ip_checksum, ip_checksum_c;
logic [(IP_SRC_ADDR_BYTES*8)-1:0] ip_src_addr, ip_src_addr_c;
logic [(IP_DST_ADDR_BYTES*8)-1:0] ip_dst_addr, ip_dst_addr_c;
logic [(UDP_DST_PORT_BYTES*8)-1:0] udp_dst_port, udp_dst_port_c;
logic [(UDP_SRC_PORT_BYTES*8)-1:0] udp_src_port, udp_src_port_c;
logic [(UDP_LENGTH_BYTES*8)-1:0] udp_length, udp_length_c;
logic [(UDP_CHECKSUM_BYTES*8)-1:0] udp_checksum, udp_checksum_c;

logic temp_wr_en;
logic [DATA_WIDTH-1:0] temp_din; 
logic temp_full;
logic temp_rd_en;
logic [DATA_WIDTH-1:0] temp_dout;
logic temp_empty;
logic [16:0] sum, sum_c;
logic [7:0] x, x_c;

fifo #(
    .FIFO_DATA_WIDTH(8),
    .FIFO_BUFFER_SIZE(2048)
) temp_data (
    .reset(reset),
    .wr_clk(clock),
    .wr_en(temp_wr_en),
    .din(temp_din),
    .full(temp_full),
    .rd_clk(clock),
    .rd_en(temp_rd_en),
    .dout(temp_dout),
    .empty(temp_empty)
);

always_ff @( posedge clock or posedge reset ) begin
    if (reset == 1'b1) begin
        state <= wait_for_sof;
        num_bytes <= 0;
        eth_dst_addr <= '0;
        eth_src_addr <= '0;
        eth_procotol <= '0;
        ip_version <= '0;
        ip_header <= '0;
        ip_type <= '0;
        ip_length <= '0;
        ip_id <= '0;
        ip_flag <= '0;
        ip_time <= '0;
        ip_protocol <= '0;
        ip_checksum <= '0;
        ip_src_addr <= '0;
        ip_dst_addr <= '0;
        udp_dst_port <= '0;
        udp_src_port <= '0;
        udp_length <= '0;
        udp_checksum <= '0;
    end else begin
        state <= state_c;
        num_bytes <= num_bytes_c;
        eth_dst_addr <= eth_dst_addr_c;
        eth_src_addr <= eth_src_addr_c;
        eth_procotol <= eth_procotol_c;
        ip_version <= ip_version_c;
        ip_header <= ip_header_c;
        ip_type <= ip_type_c;
        ip_length <= ip_length_c;
        ip_id <= ip_id_c;
        ip_flag <= ip_flag_c;
        ip_time <= ip_time_c;
        ip_protocol <= ip_protocol_c;
        ip_checksum <= ip_checksum_c;
        ip_src_addr <= ip_src_addr_c;
        ip_dst_addr <= ip_dst_addr_c;
        udp_dst_port <= udp_dst_port_c;
        udp_src_port <= udp_src_port_c;
        udp_length <= udp_length_c;
        udp_checksum <= udp_checksum_c;
    end
end

always_comb begin
    in_rd_en = 1'b0;
    dout = 8'b0;

    case (state)
        wait_for_sof: begin
            if ((in_sof == 1'b1) && (empty == 1'b0)) begin
                state_c = eth_dst_addr_state;
            end else if (empty == 1'b0) begin
                in_rd_en = 1'b1;
            end
        end

        eth_dst_addr_state: begin
            if (empty == 1'b0) begin
                eth_dst_addr_c = ($unsigned(eth_dst_addr) << 8) | (ETH_DST_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % ETH_DST_ADDR_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == ETH_DST_ADDR_BYTES-1) begin
                    state_c = eth_src_addr_state;
                end else begin
                    state_c = eth_dst_addr_state;
                end
            end
        end

        eth_src_addr_state: begin
            if (empty == 1'b0) begin
                eth_src_addr_c = ($unsigned(eth_src_addr) << 8) | (ETH_SRC_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % ETH_SRC_ADDR_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == ETH_SRC_ADDR_BYTES-1) begin
                    state_c = eth_protocol_state;
                end else begin
                    state_c = eth_src_addr_state;
                end
            end
        end

        eth_protocol_state: begin
            if (empty == 1'b0) begin
                eth_procotol_c = ($unsigned(eth_procotol) << 8) | (ETH_PROTOCOL_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % ETH_PROTOCOL_BYTES;
                in_rd_en = 1'b1;
                // there should be another condition here that says if the ethernet protocol != IP_PROTOCOL_DEF then return 0 (so reset?)
                if (num_bytes == ETH_PROTOCOL_BYTES-1) begin
                    state_c = ip_version_state;
                end else begin
                    state_c = eth_procotol_state;
                end
            end
        end

        ip_version_header_state: begin
            if (empty == 1'b0) begin
                ip_version_c = $unsigned(din[7:4]);
                ip_header_c = $unsigned(din[3:0]);
                // check the protocol matches the def
                in_rd_en = 1'b1;
                num_bytes_c = 0;
                state_c = ip_type_state;
            end
        end 

        ip_type_state: begin
            if (empty == 1'b0) begin
                ip_type_c = $unsigned(din);
                in_rd_en = 1'b1;
                state_c = ip_length_state;
            end
        end

        ip_length_state: begin
            if (empty == 1'b0) begin
                ip_length_c = ($unsigned(ip_length) << 8) | (IP_LENGTH_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_LENGTH_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_LENGTH_BYTES-1) begin
                    state_c = ip_id_state;
                end else begin
                    state_c = ip_length_state;
                end
            end
        end

        ip_id_state: begin
            if (empty == 1'b0) begin
                ip_id_c = ($unsigned(ip_id) << 8) | (IP_ID_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_ID_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_ID_BYTES-1) begin
                    state_c = ip_flag_state;
                end else begin
                    state_c = ip_id_state;
                end
            end
        end

        ip_flag_state: begin
            if (empty == 1'b0) begin
                ip_flag_c = ($unsigned(ip_flag) << 8) | (IP_FLAG_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_FLAG_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_FLAG_BYTES-1) begin
                    state_c = ip_time_state;
                end else begin
                    state_c = ip_flag_state;
                end
            end
        end

        ip_time_state: begin
            if (empty == 1'b0) begin
                ip_time_c = $unsigned(din);
                num_bytes_c = 0;
                in_rd_en = 1'b1;
                state_c = ip_protocol_state;
            end
        end

        ip_protocol_state: begin
            if (empty == 1'b0) begin
                ip_protocol_c = $unsigned(din);
                num_bytes_c = 0;
                in_rd_en = 1'b1;
                // check if ip_protocol is UDP_PROTOCOL_DEF
                state_c = ip_checksum_state;
            end
        end

        ip_checksum_state: begin
            if (empty == 1'b0) begin
                ip_checksum_c = ($unsigned(ip_checksum) << 8) | (IP_CHECKSUM_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_CHECKSUM_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_CHECKSUM_BYTES-1) begin
                    state_c = ip_src_addr_state;
                end else begin
                    state_c = ip_checksum_state;
                end
            end
        end

        ip_src_addr_state: begin
            if (empty == 1'b0) begin
                ip_src_addr_c = ($unsigned(ip_src_addr) << 8) | (IP_SRC_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_SRC_ADDR_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_SRC_ADDR_BYTES-1) begin
                    state_c = ip_dst_addr_state;
                end else begin
                    state_c = ip_src_addr_state;
                end
            end
        end

        ip_dst_addr_state: begin
            if (empty == 1'b0) begin
                ip_dst_addr_c = ($unsigned(ip_dst_addr) << 8) | (IP_DST_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_DST_ADDR_BYTES;
                if (num_bytes == IP_DST_ADDR_BYTES-1) begin
                    state_c = udp_dst_port_state;
                end else begin
                    state_c = ip_dst_addr_state;
                end
            end
        end

        udp_dst_port_state: begin
            if (empty == 1'b0) begin
                udp_dst_port_c = ($unsigned(udp_dst_port) << 8) | (UDP_DST_PORT_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_DST_PORT_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_DST_PORT_BYTES-1) begin
                    state_c = udp_src_port_state;
                end else begin
                    state_c = udp_dst_port_state;
                end
            end
        end

        udp_src_port_state: begin
            if (empty == 1'b0) begin
                udp_src_port_c = ($unsigned(udp_src_port) << 8) | (UDP_SRC_PORT_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_SRC_PORT_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_SRC_PORT_BYTES-1) begin
                    state_c = udp_length_state;
                end else begin
                    state_c = udp_src_port_state;
                end
            end
        end

        udp_length_state: begin
            if (empty == 1'b0) begin
                udp_length_c = ($unsigned(udp_length) << 8) | (UDP_LENGTH_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_LENGTH_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_LENGTH_BYTES-1) begin
                    state_c = udp_checksum_state;
                end else begin
                    state_c = udp_length_state;
                end
            end
        end

        udp_checksum_state: begin
            if (empty == 1'b0) begin
                udp_checksum_c = ($unsigned(udp_checksum) << 8) | (UDP_CHECKSUM_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_CHECKSUM_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_CHECKSUM_BYTES-1) begin
                    state_c = read_udp_data_state;
                end else begin
                    state_c = udp_checksum_state;
                end
            end
        end

        read_udp_data_state: begin
            if ((empty == 1'b0) && (in_eof == 1'b0)) begin
                temp_din = din;
                temp_wr_en = 1'b1;
                in_rd_en = 1'b1;

                num_bytes_c = (num_bytes + 1) % 2;

                if (num_bytes == 0) begin
                    x_c = 8'($unsigned(din));
                end else begin
                    x_c = 8'0
                    // if there was a carry, add it and clear it
                    if (sum[16] == 1'b1) begin
                        sum_c = (sum + ((x << 8) | 17'($unsigned(din))) + 1) & 17'h0FF;
                    end else begin
                        sum_c = sum + ((x << 8) | 17'($unsigned(din)));
                    end

                end
                
                state_c = read_udp_data_state;

            end else if (in_eof == 1'b1) begin
                state_c = calculate_checksum_state;
            end else if ((empty === 1'b1) && (in_eof == 1'b0)) begin
                state_c = read_udp_data_state;
            end
        end

        calculate_checksum_state: begin




        default: 
    endcase
end