import uvm_pkg::*;


// Reads data from output fifo to scoreboard
class my_uvm_monitor_output extends uvm_monitor;
    `uvm_component_utils(my_uvm_monitor_output)

    uvm_analysis_port#(my_uvm_transaction) mon_ap_output;

    virtual my_uvm_if vif;
    int out_file;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction: new

    virtual function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        void'(uvm_resource_db#(virtual my_uvm_if)::read_by_name
            (.scope("ifs"), .name("vif"), .val(vif)));
        mon_ap_output = new(.name("mon_ap_output"), .parent(this));

        out_file = $fopen(TXT_OUT_NAME, "wb");
        if ( !out_file ) begin
            `uvm_fatal("MON_OUT_BUILD", $sformatf("Failed to open output file %s...", TXT_OUT_NAME));
        end
    endfunction: build_phase

    virtual task run_phase(uvm_phase phase);
        int n_bytes;
        logic [0:PCAP_FILE_HEADER_SIZE-1][7:0] file_header;
        logic [0:PCAP_PACKET_HEADER_SIZE-1][7:0] packet_header;

        my_uvm_transaction tx_out;

        // wait for reset
        @(posedge vif.reset)
        @(negedge vif.reset)

        tx_out = my_uvm_transaction::type_id::create(.name("tx_out"), .contxt(get_full_name()));

        vif.out_rd_en = 1'b0;

        forever begin
            @(negedge vif.clock)
            begin
                if (vif.out_empty == 1'b0) begin
                    $fwrite(out_file, "%c", vif.out_dout);
                    tx_out.data = vif.out_dout;
                    mon_ap_output.write(tx_out);
                    vif.out_rd_en = 1'b1;
                end else begin
                    vif.out_rd_en = 1'b0;
                end
            end
        end
    endtask: run_phase

    virtual function void final_phase(uvm_phase phase);
        super.final_phase(phase);
        `uvm_info("MON_OUT_FINAL", $sformatf("Closing file %s...", TXT_OUT_NAME), UVM_LOW);
        $fclose(out_file);
    endfunction: final_phase

endclass: my_uvm_monitor_output


// Reads data from compare file to scoreboard
class my_uvm_monitor_compare extends uvm_monitor;
    `uvm_component_utils(my_uvm_monitor_compare)

    uvm_analysis_port#(my_uvm_transaction) mon_ap_compare;
    virtual my_uvm_if vif;
    int cmp_file, n_bytes;

    function new(string name, uvm_component parent);
        super.new(name, parent);
    endfunction: new

    virtual function void build_phase(uvm_phase phase);
        super.build_phase(phase);
        void'(uvm_resource_db#(virtual my_uvm_if)::read_by_name
            (.scope("ifs"), .name("vif"), .val(vif)));
        mon_ap_compare = new(.name("mon_ap_compare"), .parent(this));

        cmp_file = $fopen(TXT_CMP_NAME, "rb");
        if ( !cmp_file ) begin
            `uvm_fatal("MON_CMP_BUILD", $sformatf("Failed to open file %s...", TXT_CMP_NAME));
        end


    endfunction: build_phase

    virtual task run_phase(uvm_phase phase);
        int n_bytes=0, i=0;
        logic [7:0] dout;
        my_uvm_transaction tx_cmp;

        // extend the run_phase 20 clock cycles
        phase.phase_done.set_drain_time(this, (CLOCK_PERIOD*20));

        // notify that run_phase has started
        phase.raise_objection(.obj(this));

        // wait for reset
        @(posedge vif.reset)
        @(negedge vif.reset)

        tx_cmp = my_uvm_transaction::type_id::create(.name("tx_cmp"), .contxt(get_full_name()));

        // syncronize file read with fifo data
        while ( !$feof(cmp_file) ) begin
            @(negedge vif.clock)
            begin
                if ( vif.out_empty == 1'b0 ) begin
                    n_bytes = $fread(dout, cmp_file, i, 1);
                    tx_cmp.data = dout;
                    mon_ap_compare.write(tx_cmp);
                    i++;
                end
            end
        end        

        // notify that run_phase has completed
        phase.drop_objection(.obj(this));
    endtask: run_phase

    virtual function void final_phase(uvm_phase phase);
        super.final_phase(phase);
        `uvm_info("MON_CMP_FINAL", $sformatf("Closing file %s...", TXT_CMP_NAME), UVM_LOW);
        $fclose(cmp_file);
    endfunction: final_phase

endclass: my_uvm_monitor_compare
