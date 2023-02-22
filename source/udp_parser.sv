module udp_parser (
    input  logic        clock,
    input  logic        reset,
    input  logic        in_sof,
    input  logic        in_eof,
    input  logic [7:0]  din,
    input  logic        in_empty,
    output logic        in_rd_en,
    output logic [7:0]  dout,
    output logic        out_sof,
    output logic        out_eof,
    output logic        out_wr_en,
    output logic        out_empty,
    input  logic        out_full
);

localparam ETH_DST_ADDR_BYTES     = 6;
localparam ETH_SRC_ADDR_BYTES     = 6;
localparam ETH_PROTOCOL_BYTES     = 2;
localparam IP_VERSION_BYTES       = 1;
localparam IP_HEADER_BYTES        = 1;
localparam IP_TYPE_BYTES          = 1;
localparam IP_LENGTH_BYTES        = 2;
localparam IP_ID_BYTES            = 2;
localparam IP_FLAG_BYTES          = 2;
localparam IP_TIME_BYTES          = 1;
localparam IP_PROTOCOL_BYTES      = 1;
localparam IP_CHECKSUM_BYTES      = 2;
localparam IP_SRC_ADDR_BYTES      = 4;
localparam IP_DST_ADDR_BYTES      = 4;
localparam UDP_DST_PORT_BYTES     = 2;
localparam UDP_SRC_PORT_BYTES     = 2;
localparam UDP_LENGTH_BYTES       = 2;
localparam UDP_CHECKSUM_BYTES     = 2;
localparam IP_PROTOCOL_DEF        = 16'h0800;
localparam IP_VERSION_DEF         = 4'h4;
localparam UDP_PROTOCOL_DEF       = 8'h11;
localparam DATA_WIDTH             = 8;

typedef enum logic [4:0] { init, wait_for_sof, eth_dst_addr_state, eth_src_addr_state, eth_protocol_state, ip_version_header_state, ip_type_state, ip_length_state, ip_id_state, ip_flag_state, ip_time_state, ip_protocol_state, ip_checksum_state, ip_src_addr_state, ip_dst_addr_state, udp_dst_port_state, udp_src_port_state, udp_length_state, udp_checksum_state, read_udp_data_state, calculate_checksum_state, validate_checksum_state, output_state, done } state_t;
state_t state, state_c;

integer num_bytes, num_bytes_c;
integer udp_bytes, udp_bytes_c;
logic [(ETH_DST_ADDR_BYTES*8)-1:0] eth_dst_addr, eth_dst_addr_c;
logic [(ETH_SRC_ADDR_BYTES*8)-1:0] eth_src_addr, eth_src_addr_c;
logic [(ETH_PROTOCOL_BYTES*8)-1:0] eth_protocol, eth_protocol_c;
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

logic buffer_wr_en;
logic [DATA_WIDTH-1:0] buffer_din; 
logic buffer_full;
logic buffer_rd_en;
logic buffer_empty;
logic [31:0] sum, sum_c;
logic [7:0] x, x_c;
logic fifo_clear;
logic fifo_reset;
logic buffer_out_sof;
logic buffer_out_eof;

fifo_ctrl buffer_fifo (
    .reset(fifo_reset),
    .wr_clk(clock),
    .wr_en(buffer_wr_en),
    .wr_sof(in_sof),
    .wr_eof(in_eof),
    .din(buffer_din),
    .full(buffer_full),
    .rd_clk(clock),
    .rd_en(buffer_rd_en),
    .rd_sof(buffer_out_sof),
    .rd_eof(buffer_out_eof),
    .dout(dout),
    .empty(buffer_empty)
);

assign fifo_reset = reset || fifo_clear;
assign out_empty = buffer_empty;
assign out_sof = buffer_out_sof;
assign out_eof = buffer_out_eof;

always_ff @( posedge clock or posedge reset ) begin
    if (reset == 1'b1) begin
        state <= init;
        num_bytes <= 0;
        udp_bytes <= 0;
        eth_dst_addr <= '0;
        eth_src_addr <= '0;
        eth_protocol <= '0;
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
        sum <= '0;
        x <= '0;
    end else begin
        state <= state_c;
        num_bytes <= num_bytes_c;
        udp_bytes <= udp_bytes_c;
        eth_dst_addr <= eth_dst_addr_c;
        eth_src_addr <= eth_src_addr_c;
        eth_protocol <= eth_protocol_c;
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
        sum <= sum_c;
        x <= x_c;
    end
end

always_comb begin
    in_rd_en = 1'b0;
    fifo_clear = 1'b0;
    out_wr_en = 1'b0;
    buffer_rd_en = 1'b0;
    buffer_wr_en = 1'b0;
    buffer_din = '0;
    

    case (state)
        init: begin
            num_bytes_c = 0;
            udp_bytes_c = 0;
            sum_c = '0;
            x_c = '0;
            buffer_din = '0;
            buffer_rd_en = 1'b0;
            buffer_wr_en = 1'b0;
            out_wr_en = 1'b0;
            state_c = wait_for_sof;
        end

        wait_for_sof: begin
            if ((in_sof == 1'b1) && (in_empty== 1'b0)) begin
                state_c = eth_dst_addr_state;
            end else if (in_empty== 1'b0) begin
                in_rd_en = 1'b1;
            end
        end

        eth_dst_addr_state: begin
            if (in_empty== 1'b0) begin
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
            if (in_empty== 1'b0) begin
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
            if (in_empty== 1'b0) begin
                eth_protocol_c = ($unsigned(eth_protocol) << 8) | (ETH_PROTOCOL_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % ETH_PROTOCOL_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == ETH_PROTOCOL_BYTES-1) begin
                    // check protocol here
                    if (eth_protocol_c != IP_PROTOCOL_DEF) begin
                        fifo_clear = 1'b1;
                        state_c = init;
                    end else begin
                        state_c = ip_version_header_state;
                    end 
                end
            end else begin
                state_c = eth_protocol_state;
            end
        end

        ip_version_header_state: begin
            if (in_empty== 1'b0) begin
                ip_version_c = $unsigned(din[7:4]);
                ip_header_c = $unsigned(din[3:0]);
                // check the protocol matches the def
                in_rd_en = 1'b1;
                num_bytes_c = 0;
                if (ip_version_c != IP_VERSION_DEF) begin
                    fifo_clear = 1'b1;
                    state_c = init;
                end else begin
                    state_c = ip_type_state;
                end
            end else begin
                state_c = ip_version_header_state;
            end
        end 

        ip_type_state: begin
            if (in_empty== 1'b0) begin
                ip_type_c = $unsigned(din);
                in_rd_en = 1'b1;
                state_c = ip_length_state;
            end
        end

        ip_length_state: begin
            if (in_empty== 1'b0) begin
                ip_length_c = ($unsigned(ip_length) << 8) | (IP_LENGTH_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_LENGTH_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == IP_LENGTH_BYTES-1) begin
                    // add to checksum_c
                    sum_c = sum + 32'({16'h0000, $unsigned(ip_length_c)}) - 32'($unsigned(32'd20));
                    state_c = ip_id_state;
                end else begin
                    state_c = ip_length_state;
                end
            end
        end

        ip_id_state: begin
            if (in_empty== 1'b0) begin
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
            if (in_empty== 1'b0) begin
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
            if (in_empty== 1'b0) begin
                // if ttl is 0, exit
                ip_time_c = $unsigned(din);
                num_bytes_c = 0;
                in_rd_en = 1'b1;

                if (ip_time_c == 8'h00) begin
                    fifo_clear = 1'b1;
                    state_c = init;
                end else begin
                    state_c = ip_protocol_state;
                end
            end
        end

        ip_protocol_state: begin
            if (in_empty== 1'b0) begin
                ip_protocol_c = $unsigned(din);
                num_bytes_c = 0;
                in_rd_en = 1'b1;
                // check if ip_protocol is UDP_PROTOCOL_DEF
                if (ip_protocol_c != UDP_PROTOCOL_DEF) begin
                    fifo_clear = 1'b1;
                    state_c = init;
                end else begin
                    sum_c = sum + 32'({24'h000000, $unsigned(ip_protocol_c)});
                    state_c = ip_checksum_state;
                end
            end
        end

        ip_checksum_state: begin
            if (in_empty== 1'b0) begin
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
            if (in_empty== 1'b0) begin
                ip_src_addr_c = ($unsigned(ip_src_addr) << 8) | (IP_SRC_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_SRC_ADDR_BYTES;
                in_rd_en = 1'b1;

                if (num_bytes % 2 == 1) begin
                    sum_c = sum + 32'({16'h0000, $unsigned(ip_src_addr_c[15:0])});
                end

                if (num_bytes == IP_SRC_ADDR_BYTES-1) begin
                    state_c = ip_dst_addr_state;
                end else begin
                    state_c = ip_src_addr_state;
                end
            end
        end

        ip_dst_addr_state: begin
            if (in_empty== 1'b0) begin
                ip_dst_addr_c = ($unsigned(ip_dst_addr) << 8) | (IP_DST_ADDR_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % IP_DST_ADDR_BYTES;
                in_rd_en = 1'b1;

                if (num_bytes % 2 == 1) begin
                    sum_c = sum + 32'({16'h0000, $unsigned(ip_dst_addr_c[15:0])});
                end
                
                if (num_bytes == IP_DST_ADDR_BYTES-1) begin
                    state_c = udp_dst_port_state;
                end else begin
                    state_c = ip_dst_addr_state;
                end
            end
        end

        udp_dst_port_state: begin
            if (in_empty== 1'b0) begin
                udp_dst_port_c = ($unsigned(udp_dst_port) << 8) | (UDP_DST_PORT_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_DST_PORT_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_DST_PORT_BYTES-1) begin
                    sum_c = sum + 32'({16'h0000, $unsigned(udp_dst_port_c)});
                    state_c = udp_src_port_state;
                end else begin
                    state_c = udp_dst_port_state;
                end
            end
        end

        udp_src_port_state: begin
            if (in_empty== 1'b0) begin
                udp_src_port_c = ($unsigned(udp_src_port) << 8) | (UDP_SRC_PORT_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_SRC_PORT_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_SRC_PORT_BYTES-1) begin
                    sum_c = sum + 32'({16'h0000, $unsigned(udp_src_port_c)});
                    state_c = udp_length_state;
                end else begin
                    state_c = udp_src_port_state;
                end
            end
        end

        udp_length_state: begin
            if (in_empty== 1'b0) begin
                udp_length_c = ($unsigned(udp_length) << 8) | (UDP_LENGTH_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_LENGTH_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_LENGTH_BYTES-1) begin
                    sum_c = sum + 32'({16'h0000, $unsigned(udp_length_c)});
                    state_c = udp_checksum_state;
                end else begin
                    state_c = udp_length_state;
                end
            end
        end

        udp_checksum_state: begin
            if (in_empty== 1'b0) begin
                udp_checksum_c = ($unsigned(udp_checksum) << 8) | (UDP_CHECKSUM_BYTES*8)'($unsigned(din));
                num_bytes_c = (num_bytes + 1) % UDP_CHECKSUM_BYTES;
                in_rd_en = 1'b1;
                if (num_bytes == UDP_CHECKSUM_BYTES-1) begin
                    udp_bytes_c = 0;
                    state_c = read_udp_data_state;
                end else begin
                    state_c = udp_checksum_state;
                end
            end
        end

        read_udp_data_state: begin
            // make sure buffer fifo not full
            if ((in_empty== 1'b0) && (buffer_full == 1'b0)) begin
                buffer_din = din;
                buffer_wr_en = 1'b1;
                in_rd_en = 1'b1;
                udp_bytes_c = udp_bytes + 1;
                num_bytes_c = (num_bytes + 1) % 2;

                if (num_bytes == 0) begin
                    x_c = 8'($unsigned(din));
                end else begin
                    sum_c = sum + 32'({16'h0000, x, $unsigned(din)});
                end

                if (in_eof == 1'b1 || udp_bytes == udp_length - (UDP_CHECKSUM_BYTES + UDP_LENGTH_BYTES + UDP_DST_PORT_BYTES + UDP_SRC_PORT_BYTES) - 1) begin
                    if (udp_length[0] == 1'b1) begin
                        sum_c = sum + 32'({16'h0000, $unsigned(din), 8'h00});
                    end
                    state_c = calculate_checksum_state;
                end
            end
        end

        calculate_checksum_state: begin
            // if top 16 bits of checksum not 0, add top 16 to bottom 16, then invert bottom 16 to validate
            if (sum[31:16] != 16'h0000) begin
                sum_c = {16'h0000, $unsigned(sum[31:16])} + {16'h0000, $unsigned(sum[15:0])};
            end else begin
                sum_c = ~sum;
                state_c = validate_checksum_state;
            end
        end

        validate_checksum_state: begin
            if (sum[15:0] != udp_checksum) begin
                fifo_clear = 1'b1;
                state_c = init;
            end else begin
                state_c = output_state;
            end
        end

        output_state: begin
            if (buffer_empty == 1'b0 && out_full == 1'b0) begin
                buffer_rd_en = 1'b1;
                out_wr_en = 1'b1;
            end
            if (buffer_out_eof == 1'b1) begin
                state_c = done;
            end
        end

        done: begin
            fifo_clear = 1'b1;
            state_c = init;
        end

    endcase
end
endmodule