module fifo_ctrl #(
    parameter DATA_FIFO_DATA_WIDTH = 8,
    parameter FRAME_SYNC_FIFO_DATA_WIDTH = 2,
    parameter FIFO_BUFFER_SIZE = 1024,
)
(
    input  logic                            reset,
    input  logic                            wr_clk,
    input  logic                            wr_en,
    input  logic                            wr_sof,
    input  logic                            wr_eof,
    input  logic [DATA_FIFO_DATA_WIDTH-1:0] din,
    output logic                            full,

    input  logic                            rd_clk,
    input  logic                            rd_en,
    output logic                            rd_sof,
    output logic                            rd_eof,
    output logic [DATA_FIFO_DATA_WIDTH-1:0] dout,
    output logic                            empty
);

logic dif_empty, fsf_empty;
logic dif_full, fsf_full;

fifo #(
    .FIFO_DATA_WIDTH(DATA_FIFO_DATA_WIDTH),
    .FIFO_BUFFER_SIZE(FIFO_BUFFER_SIZE)
) data_in_fifo (
    .reset(reset),
    .wr_clk(wr_clk),
    .wr_en(wr_en),
    .din(din),
    .full(dif_full),
    .rd_clk(rd_clk),
    .rd_en(rd_en),
    .dout(dout),
    .empty(dif_empty)
);

fifo #(
    .FIFO_DATA_WIDTH(FRAME_SYNC_FIFO_DATA_WIDTH),
    .FIFO_BUFFER_SIZE(FIFO_BUFFER_SIZE)
) frame_sync_fifo (
    .reset(reset),
    .wr_clk(wr_clk),
    .wr_en(wr_en),
    .din({wr_sof, wr_eof}),
    .full(fsf_full),
    .rd_clk(rd_clk),
    .rd_en(rd_en),
    .dout({rd_sof, rd_eof}),
    .empty(fsf_empty)
);

assign empty = dif_empty || fsf_empty;
assign full = dif_full || fsf_full;

endmodule


