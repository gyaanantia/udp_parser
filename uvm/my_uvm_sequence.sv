import uvm_pkg::*;


class my_uvm_transaction extends uvm_sequence_item;
    logic [7:0] data;
    logic wr_en;
    logic sof;
    logic eof;

    function new(string name = "");
        super.new(name);
    endfunction: new

    `uvm_object_utils_begin(my_uvm_transaction)
        `uvm_field_int(data, UVM_ALL_ON)
    `uvm_object_utils_end
endclass: my_uvm_transaction


class my_uvm_sequence extends uvm_sequence#(my_uvm_transaction);
    `uvm_object_utils(my_uvm_sequence)

    function new(string name = "");
        super.new(name);
    endfunction: new

    task body();        
        my_uvm_transaction tx;
        // int in_file, n_bytes=0, i=0;

        int i, j;
        int n_bytes;
        int packet_size;
        int in_file, cmp_file;
        logic [0:PCAP_FILE_HEADER_SIZE-1] [7:0] file_header;
        logic [0:PCAP_PACKET_HEADER_SIZE-1] [7:0] packet_header;
        logic [7:0] din;

        `uvm_info("SEQ_RUN", $sformatf("Loading file %s...", PCAP_IN_NAME), UVM_LOW);

        in_file = $fopen(PCAP_IN_NAME, "rb");
        cmp_file = $fopen(TXT_CMP_NAME, "rb");

        if ( !in_file ) begin
            `uvm_fatal("SEQ_RUN", $sformatf("Failed to open file %s...", PCAP_IN_NAME));
        end

        i = $fseek(cmp_file, 0, 2);
        n_bytes = $ftell(cmp_file);
        i = $fseek(cmp_file, 0, 0);
        $fclose(cmp_file);

        // read PCAP header
        i = $fread(file_header, in_file, 0, PCAP_FILE_HEADER_SIZE);
        if ( !i ) begin
            `uvm_fatal("SEQ_RUN", $sformatf("Failed read header data from %s...", PCAP_IN_NAME));
        end


        while ( !$feof(in_file) && i < n_bytes ) begin
            // read packet header
            packet_header = {(PCAP_PACKET_HEADER_SIZE){8'h00}};
            i += $fread(packet_header, in_file, i, PCAP_PACKET_HEADER_SIZE);
            packet_size = {<<8{packet_header[8:11]}};
            `uvm_info("SEQ_RUN", $sformatf("Packet size: %d", packet_size), UVM_LOW);

            // read packet data
            j = 0;
            while (j < packet_size) begin
                tx = my_uvm_transaction::type_id::create(.name("tx"), .contxt(get_full_name()));
                start_item(tx);
                i += $fread(din, in_file, i, 1);
                tx.wr_en = 1'b1;
                tx.sof = (j == 0) ? 1'b1 : 1'b0;
                tx.eof = (j == packet_size-1) ? 1'b1 : 1'b0;
                tx.data = din;
                finish_item(tx);
                j++;
            end
        end

        `uvm_info("SEQ_RUN", $sformatf("Closing file %s...", PCAP_IN_NAME), UVM_LOW);
        $fclose(in_file);
    endtask: body
endclass: my_uvm_sequence

typedef uvm_sequencer#(my_uvm_transaction) my_uvm_sequencer;
