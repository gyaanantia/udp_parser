import uvm_pkg::*;

interface my_uvm_if;
    logic       clock;
    logic       reset;
    logic [7:0] in_din;
    logic       in_wr_en;
    logic       in_wr_sof;
    logic       in_wr_eof;
    logic       in_full;  
    logic       out_rd_en;
    logic       out_rd_sof;
    logic       out_rd_eof;
    logic [7:0] out_dout;
    logic       out_empty;
    
endinterface
