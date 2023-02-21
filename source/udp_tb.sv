`timescale 1ns/1ns

module udp_tb;

localparam PCAP_IN_NAME = "../test.pcap";
localparam TXT_OUT_NAME = "../output.txt";
localparam TXT_CMP_NAME = "../test_output.txt";
localparam PCAP_FILE_HEADER_SIZE = 24;
localparam PCAP_PACKET_HEADER_SIZE = 16;

localparam CLOCK_PERIOD = 10;

logic       clock         = 1'b1;
logic       reset         = '0;
logic       start         = '0;

logic [7:0] in_din;
logic       in_wr_en      = '0;
logic       in_wr_sof     = '0;
logic       in_wr_eof     = '0;
logic       in_full;

logic       out_rd_en;
logic       out_rd_sof;
logic       out_rd_eof;
logic [7:0] out_dout;
logic       out_empty;

logic       in_write_done = '0;
logic       out_read_done = '0;
integer     out_errors    = '0;

udp dut (
    .clock(clock),
    .reset(reset),
    .in_din(in_din),
    .in_wr_en(in_wr_en),
    .in_wr_sof(in_wr_sof),
    .in_wr_eof(in_wr_eof),
    .in_full(in_full),
    .out_rd_en(out_rd_en),
    .out_rd_sof(out_rd_sof),
    .out_rd_eof(out_rd_eof),
    .out_dout(out_dout),
    .out_empty(out_empty)
);

always begin
    clock = 1'b1;
    #(CLOCK_PERIOD/2);
    clock = 1'b0;
    #(CLOCK_PERIOD/2);
end

initial begin
    @(posedge clock);
    reset = 1'b1;
    @(posedge clock);
    reset = 1'b0;
end

initial begin : tb_process
    longint unsigned start_time, end_time;

    @(negedge reset);
    @(posedge clock);
    start_time = $time;

    // start
    $display("@ %0t: Beginning simulation...", start_time);
    start = 1'b1;
    @(posedge clock);
    start = 1'b0;

    wait(out_read_done);
    end_time = $time;

    // report metrics
    $display("@ %0t: Simulation completed.", end_time);
    $display("Total simulation cycle count: %0d", (end_time-start_time)/CLOCK_PERIOD);
    $display("Total error count: %0d", out_errors);

    // end the simulation
    $finish;
end

initial begin : pcap_read_process
    int i, j;
    int packet_size;
    int in_file;
    logic [0:PCAP_FILE_HEADER_SIZE-1] [7:0] file_header;
    logic [0:PCAP_PACKET_HEADER_SIZE-1] [7:0] packet_header;

    @(negedge reset);
    $display("@ %0t: Loading file %s...", $time, PCAP_IN_NAME);

    in_file = $fopen(PCAP_IN_NAME, "rb");
    in_wr_en = 1'b0;
    in_wr_sof = 1'b0;
    in_wr_eof = 1'b0;

    // Skip PCAP Global header
    i = $fread(file_header, in_file, 0, PCAP_FILE_HEADER_SIZE);

    // Read data from image file
    while (!$feof(in_file)) begin
        // read pcap packet header and get packet length
        packet_header = {(PCAP_PACKET_HEADER_SIZE){8'h00}};
        i += $fread(packet_header, in_file, i, PCAP_PACKET_HEADER_SIZE);
        packet_size = {<<6{packet_header[8:11]}};
        $display("Packet size: %d", packet_size);

        // iterate through packet length
        j = 0;
        while ( j < packet_size ) begin
            @(negedge clock);
            if (in_full == 1'b0) begin
                i += $fread(in_din, in_file, i, 1);
                in_wr_en = 1'b1;
                in_wr_sof = j == 0 ? 1'b1 : 1'b0;
                in_wr_eof = j == packet_size-1 ? 1'b1 : 1'b0;
                j++;
            end else begin
                in_wr_en = 1'b0;
                in_wr_sof = 1'b0;
                in_wr_eof = 1'b0;
            end
        end
    end

    @(negedge clock);
    in_wr_en = 1'b0;
    in_wr_sof = 1'b0;
    in_wr_eof = 1'b0;
    $fclose(in_file);
    in_write_done = 1'b1;
end

initial begin : txt_write_process
    int i, n_bytes, r;
    int out_file;
    int cmp_file;
    logic [7:0] cmp_dout;

    @(negedge reset);
    @(negedge clock);

    $display("@ %0t: Comparing file %s...", $time, TXT_OUT_NAME);

    out_file = $fopen(TXT_OUT_NAME, "wb");
    cmp_file = $fopen(TXT_CMP_NAME, "rb");
    out_rd_en = 1'b0;

    i = $fseek(cmp_file, 0, 2);
    n_bytes = $ftell(cmp_file);
    i = $fseek(cmp_file, 0, 0);

    while (i < n_bytes) begin
        @(negedge clock);
        out_rd_en = 1'b0;
        if (out_empty == 1'b0) begin
            r = $fread(cmp_dout, cmp_file, i, 1);
            $fwrite(out_file, "%c", out_dout);

            if (cmp_dout != out_dout) begin
                out_errors += 1;
                $write("@ %0t: %s(%0d): ERROR %x != %x at address0x%x.\n", $time, TXT_OUT_NAME, i+1, out_dout, cmp_dout, i);
            end
            out_rd_en = 1'b1;
            i++;
        end
    end

    @(negedge clock);
    out_rd_en = 1'b0;
    $fclose(out_file);
    $fclose(cmp_file);
    out_read_done = 1'b1;
end

endmodule
