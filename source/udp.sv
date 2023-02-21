module udp (
    input  logic        clock,
    input  logic        reset,
    input  logic [7:0]  in_din,
    input  logic        in_wr_en,
    input  logic        in_wr_sof,
    input  logic        in_wr_eof,
    output logic        in_full,

    input  logic        out_rd_en,
    output logic        out_rd_sof,
    output logic        out_rd_eof,
    output logic [7:0]  out_dout,
    output logic        out_empty
);

logic in_rd_en;
logic in_sof;
logic in_eof;
logic [7:0] in_dout;
logic in_empty;

logic [7:0] parser_dout;
logic parser_sof;
logic parser_eof;
logic parser_empty;
logic parser_out_wr_en;

logic out_full;

fifo_ctrl input_fifo (
    .reset(reset),
    .wr_clk(clock),
    .wr_en(in_wr_en),
    .wr_sof(in_wr_sof),
    .wr_eof(in_wr_eof),
    .din(in_din),
    .full(in_full),
    .rd_clk(clock),
    .rd_en(in_rd_en),
    .rd_sof(in_sof),
    .rd_eof(in_eof),
    .dout(in_dout),
    .empty(in_empty)
);

udp_parser parser (
    .clock(clock),
    .reset(reset),
    .in_sof(in_sof),
    .in_eof(in_eof),
    .din(in_dout),
    .in_empty(in_empty),
    .in_rd_en(in_rd_en),
    .dout(parser_dout),
    .out_sof(parser_sof),
    .out_eof(parser_eof),
    .out_wr_en(parser_out_wr_en),
    .out_empty(parser_empty),
    .out_full(out_full)
);

fifo_ctrl output_fifo (
    .reset(reset),
    .wr_clk(clock),
    .wr_en(parser_out_wr_en),
    .wr_sof(parser_sof),
    .wr_eof(parser_eof),
    .din(parser_dout),
    .full(out_full),
    .rd_clk(clock),
    .rd_en(out_rd_en),
    .rd_sof(out_rd_sof),
    .rd_eof(out_rd_eof),
    .dout(out_dout),
    .empty(out_empty)
);

endmodule