// MIT License

// Copyright (c) 2025 KU Leuven - COSIC

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/*
 * From our research paper "High-Performance Hardware Implementation of CRYSTALS-Dilithium"
 * by Luke Beckwith, Duc Tri Nguyen, Kris Gaj
 * at George Mason University, USA
 * https://eprint.iacr.org/2021/1451.pdf
 * =============================================================================
 * Copyright (c) 2021 by Cryptographic Engineering Research Group (CERG)
 * ECE Department, George Mason University
 * Fairfax, VA, U.S.A.
 * Author: Luke Beckwith
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 * @author   Luke Beckwith <lbeckwit@gmu.edu>
 */
 
`include "../../common/mldsa_params.v"

// ML-DSA TESTVECTORS ARE OBTAINED FORM: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json

// CLock settings
`timescale 1ns / 1ps
`define P 10

// Number of test vectors per parameter set, e.g. xvlog -d NUM_TV_87=3 (0 skips that set)
`ifndef NUM_TV_44
`define NUM_TV_44 25
`endif
`ifndef NUM_TV_65
`define NUM_TV_65 25
`endif
`ifndef NUM_TV_87
`define NUM_TV_87 25
`endif

module tb_keygen_top;
    reg clk = 1, rst = 0, start = 0;

    reg [2 - 1 : 0] mode = 0; // KeyGen()
    reg [3 - 1 : 0] sec_lvl = 2; // ML-DSA-44
      
    localparam NUM_TV_2 = `NUM_TV_44;
    localparam NUM_TV_3 = `NUM_TV_65;
    localparam NUM_TV_5 = `NUM_TV_87;
    localparam NUM_TV_23 = (NUM_TV_2 > NUM_TV_3) ? NUM_TV_2 : NUM_TV_3;
    localparam NUM_TV = (NUM_TV_23 > NUM_TV_5) ? NUM_TV_23 : NUM_TV_5; // array depth
      
    reg valid_i, ready_o;
    wire ready_i, valid_o;
    reg  [64 - 1 : 0] data_i;  
    wire [64 - 1 : 0] data_o;
    
    combined_top DUT (
        clk,
        rst,
        start,
        mode,
        sec_lvl,
        valid_i,
        ready_i,
        data_i,
        valid_o,
        ready_o,
        data_o
    );
    
    reg [`SEED_WIDTH - 1 : 0]   seed_2  [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_2 - 1]   pk_2    [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_2 - 1]   pk_2_out                ;
    reg [0 : `SK_WIDTH_2 - 1]   sk_2    [NUM_TV - 1 : 0];
    reg [0 : `SK_WIDTH_2 - 1]   sk_2_out                ;

    reg [`SEED_WIDTH - 1 : 0]   seed_3  [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_3 - 1]   pk_3    [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_3 - 1]   pk_3_out               ;
    reg [0 : `SK_WIDTH_3 - 1]   sk_3    [NUM_TV - 1 : 0];
    reg [0 : `SK_WIDTH_3 - 1]   sk_3_out                ;       
    
    reg [`SEED_WIDTH - 1 : 0]   seed_5  [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_5 - 1]   pk_5    [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_5 - 1]   pk_5_out                ;
    reg [0 : `SK_WIDTH_5 - 1]   sk_5    [NUM_TV - 1 : 0];
    reg [0 : `SK_WIDTH_5 - 1]   sk_5_out                ;
    
    reg [16 - 1 : 0]    c; // current testvector
    reg [32 - 1 : 0]    ctr; // current data_word

    integer start_time, i;
    integer n_pass = 0, n_fail = 0;
    reg     vec_err = 0;

    task finish_tb;
    begin
        $display("TEST SUMMARY: %0d passed, %0d failed", n_pass, n_fail);
        $finish;
    end
    endtask
    integer average;
  
    localparam
        S_INIT          = 4'd0,
        S_START         = 4'd1,
        S_SEND_SEED     = 4'd2,
        S_RECV_SKPK_rho = 4'd3,
        S_RECV_SK_K     = 4'd4,
        S_RECV_SK_s1    = 4'd5,
        S_RECV_SK_s2    = 4'd6,
        S_RECV_PK_t1    = 4'd7,
        S_RECV_SK_t0    = 4'd8,
        S_RECV_SK_tr    = 4'd9,
        S_CHECK_PK      = 4'd10,
        S_CHECK_SK      = 4'd11,
        S_STOP          = 4'd12;
    
    reg [4 - 1 : 0] state = 0;    
  
    initial begin
        // KAT Inputs
        $readmemh("KeyGen_seed_44.txt",  seed_2);
        $readmemh("KeyGen_seed_65.txt",  seed_3);
        $readmemh("KeyGen_seed_87.txt",  seed_5);
        
        // KAT Outputs
        $readmemh("KeyGen_pk_44.txt", pk_2);
        $readmemh("KeyGen_pk_65.txt", pk_3);
        $readmemh("KeyGen_pk_87.txt", pk_5);
        
        $readmemh("KeyGen_sk_44.txt", sk_2);
        $readmemh("KeyGen_sk_65.txt", sk_3);
        $readmemh("KeyGen_sk_87.txt", sk_5);
        
        valid_i = 0;
        ready_o = 0;
        data_i  = 0;
        ctr     = 0; 
        c       = 0;
        average = 0;

        pk_2_out = 0;
        sk_2_out = 0;
        pk_3_out = 0;
        sk_3_out = 0;
        pk_5_out = 0;
        sk_5_out = 0;
    end
  
    always @(posedge clk) begin
        rst     <= 0;
        valid_i <= 0;
        start   <= 0;
        ready_o <= 0;
        
        case(sec_lvl)
        2: begin
            case(state)
            S_INIT: if (NUM_TV_2 == 0) sec_lvl <= 3; else begin
                start_time <= $time;
                rst <= 1;
                ctr <= ctr + 1;
                data_i <= seed_2[c][`SEED_WIDTH - 1 -: 64];
                if (ctr == 3) begin
                    ctr <= 1;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                state <= S_SEND_SEED;
            end
            S_SEND_SEED: begin
                valid_i <= (!ready_i) ? 1 : 0;
               
                if (ready_i) begin
                    ctr <= ctr + 1;
                    valid_i <= 1;
                    data_i <= seed_2[c][`SEED_WIDTH - ctr*64 - 1 -: 64];
                    if (ctr * 8 == `SEED_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SKPK_rho;
                    end
                end 
            end
            S_RECV_SKPK_rho: begin 
                ready_o <= 1; 
                if (valid_o) begin
                    pk_2_out[0 + ctr*64 +: 64] <= data_o;
                    sk_2_out[0 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_K;
                    end
                end
            end
            S_RECV_SK_K: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_2_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_K_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s1;
                    end
                end
            end
            S_RECV_SK_s1: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_2_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s1_BYTES_2 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s2;
                    end
                end
            end
            S_RECV_SK_s2: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_2_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_2 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s2_BYTES_2 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_PK_t1;
                    end
                end
            end
            S_RECV_PK_t1: begin
                ready_o <= 1;
                if (valid_o) begin
                    pk_2_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `PK_t1_BYTES_2 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_t0;
                    end
                end
            end
            S_RECV_SK_t0: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_2_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_2 + `SK_s2_WIDTH_2 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_t0_BYTES_2 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_tr;
                    end
                end
            end
            S_RECV_SK_tr: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_2_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_tr_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_CHECK_PK;

                        $display("ML-DSA-II.KeyGen, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                        average = average + ($time-start_time)/`P;
                    end
                end
            end
            S_CHECK_PK: begin
                ready_o <= 1;
                for (i = 0; i < `PK_BYTES_2; i = i + 1) begin
                    if (pk_2_out[i*8 +: 8] !== pk_2[c][i*8 +: 8])
                        begin $display("[ML-DSA-II.KeyGen, KAT #%d, byte pk{%d}] WRONG: Expected %h, received %h", c, i+1, pk_2[c][i*8 +: 8], pk_2_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_CHECK_SK;
            end        
            S_CHECK_SK: begin
                ready_o <= 1;
                for (i = 0; i < `SK_BYTES_2; i = i + 1) begin
                    if (sk_2_out[i*8 +: 8] !== sk_2[c][i*8 +: 8])
                        begin $display("[ML-DSA-II.KeyGen, KAT #%d, byte sk{%d}] WRONG: Expected %h, received %h", c, i+1, sk_2[c][i*8 +: 8], sk_2_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_STOP;
            end
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;

                if (c == NUM_TV_2-1) begin
                    c <= 0;
                    sec_lvl <= 3;
                    $display ("Moving to ML-DSA-III.KeyGen. ML-DSA-II completed in avg. %d clock cycles", average/NUM_TV_2);
                    average <= 0;
                end
            end
            endcase
        end
        3: begin
            case(state)
            S_INIT: if (NUM_TV_3 == 0) sec_lvl <= 5; else begin
                start_time = $time;
                rst <= 1;
                ctr <= ctr + 1;
                
                data_i <= seed_3[c][`SEED_WIDTH - 1 -: 64];
                if (ctr == 3) begin
                    ctr <= 1;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                state <= S_SEND_SEED;
            end
            S_SEND_SEED: begin
                valid_i <= (!ready_i) ? 1 : 0;
               
                if (ready_i) begin
                    ctr <= ctr + 1;
                    valid_i <= 1;
                    data_i <= seed_3[c][`SEED_WIDTH - ctr*64 - 1 -: 64];
                    if (ctr * 8 == `SEED_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SKPK_rho;
                    end
                end 
            end
            S_RECV_SKPK_rho: begin 
                ready_o <= 1; 
                if (valid_o) begin
                    pk_3_out[0 + ctr*64 +: 64] <= data_o;
                    sk_3_out[0 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_K;
                    end
                end
            end
            S_RECV_SK_K: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_3_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_K_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s1;
                    end
                end
            end
            S_RECV_SK_s1: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_3_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s1_BYTES_3 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s2;
                    end
                end
            end
            S_RECV_SK_s2: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_3_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_3 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s2_BYTES_3 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_PK_t1;
                    end
                end
            end
            S_RECV_PK_t1: begin
                ready_o <= 1;
                if (valid_o) begin
                    pk_3_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `PK_t1_BYTES_3 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_t0;
                    end
                end
            end
            S_RECV_SK_t0: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_3_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_3 + `SK_s2_WIDTH_3 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_t0_BYTES_3 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_tr;
                    end
                end
            end
            S_RECV_SK_tr: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_3_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_tr_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_CHECK_PK;

                        $display("ML-DSA-III.KeyGen, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                        average = average + ($time-start_time)/`P;
                    end
                end
            end
            S_CHECK_PK: begin
                ready_o <= 1;
                for (i = 0; i < `PK_BYTES_3; i = i + 1) begin
                    if (pk_3_out[i*8 +: 8] !== pk_3[c][i*8 +: 8])
                        begin $display("[ML-DSA-III.KeyGen, KAT #%d, byte pk{%d}] WRONG: Expected %h, received %h", c, i+1, pk_3[c][i*8 +: 8], pk_3_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_CHECK_SK;
            end        
            S_CHECK_SK: begin
                ready_o <= 1;
                for (i = 0; i < `SK_BYTES_3; i = i + 1) begin
                    if (sk_3_out[i*8 +: 8] !== sk_3[c][i*8 +: 8])
                        begin $display("[ML-DSA-III.KeyGen, KAT #%d, byte sk{%d}] WRONG: Expected %h, received %h", c, i+1, sk_3[c][i*8 +: 8], sk_3_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_STOP;
            end
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;

                if (c == NUM_TV_3-1) begin
                    c <= 0;
                    sec_lvl <= 5;
                    $display ("Moving to ML-DSA-V.KeyGen. ML-DSA-III completed in avg. %d clock cycles", average/NUM_TV_3);
                    average <= 0;
                end
            end
            endcase
        end
        5: begin
            case(state)
            S_INIT: if (NUM_TV_5 == 0) finish_tb; else begin
                start_time = $time;
                rst <= 1;
                ctr <= ctr + 1;
                
                data_i <= seed_5[c][`SEED_WIDTH - 1 -: 64];
                if (ctr == 3) begin
                    ctr <= 1;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                state <= S_SEND_SEED;
            end
            S_SEND_SEED: begin
                valid_i <= (!ready_i) ? 1 : 0;
               
                if (ready_i) begin
                    ctr <= ctr + 1;
                    valid_i <= 1;
                    data_i <= seed_5[c][`SEED_WIDTH - ctr*64 - 1 -: 64];
                    if (ctr * 8 == `SEED_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SKPK_rho;
                    end
                end 
            end
            S_RECV_SKPK_rho: begin 
                ready_o <= 1; 
                if (valid_o) begin
                    pk_5_out[0 + ctr*64 +: 64] <= data_o;
                    sk_5_out[0 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_K;
                    end
                end
            end
            S_RECV_SK_K: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_5_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_K_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s1;
                    end
                end
            end
            S_RECV_SK_s1: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_5_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s1_BYTES_5 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_s2;
                    end
                end
            end
            S_RECV_SK_s2: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_5_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_5 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_s2_BYTES_5 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_PK_t1;
                    end
                end
            end
            S_RECV_PK_t1: begin
                ready_o <= 1;
                if (valid_o) begin
                    pk_5_out[`SKPK_RHO_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `PK_t1_BYTES_5 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_t0;
                    end
                end
            end
            S_RECV_SK_t0: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_5_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + `SK_tr_WIDTH + `SK_s1_WIDTH_5 + `SK_s2_WIDTH_5 + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_t0_BYTES_5 - 8) begin
                        ctr <= 0;
                        state <= S_RECV_SK_tr;
                    end
                end
            end
            S_RECV_SK_tr: begin
                ready_o <= 1;
                if (valid_o) begin
                    sk_5_out[`SKPK_RHO_WIDTH + `SK_K_WIDTH + ctr*64 +: 64] <= data_o;

                    ctr <= ctr + 1;
                    if (ctr * 8 == `SK_tr_BYTES - 8) begin
                        ctr <= 0;
                        state <= S_CHECK_PK;

                        $display("ML-DSA-V.KeyGen, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                        average = average + ($time-start_time)/`P;
                    end
                end
            end
            S_CHECK_PK: begin
                ready_o <= 1;
                for (i = 0; i < `PK_BYTES_5; i = i + 1) begin
                    if (pk_5_out[i*8 +: 8] !== pk_5[c][i*8 +: 8])
                        begin $display("[ML-DSA-V.KeyGen, KAT #%d, byte pk{%d}] WRONG: Expected %h, received %h", c, i+1, pk_5[c][i*8 +: 8], pk_5_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_CHECK_SK;
            end        
            S_CHECK_SK: begin
                ready_o <= 1;
                for (i = 0; i < `SK_BYTES_5; i = i + 1) begin
                    if (sk_5_out[i*8 +: 8] !== sk_5[c][i*8 +: 8])
                        begin $display("[ML-DSA-V.KeyGen, KAT #%d, byte sk{%d}] WRONG: Expected %h, received %h", c, i+1, sk_5[c][i*8 +: 8], sk_5_out[i*8 +: 8]); vec_err = 1; end 
                end
                
                state <= S_STOP;
            end
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;

                if (c == NUM_TV_5-1) begin
                    c <= 0;
                    $display ("ML-DSA.KeyGen testbench done. ML-DSA-V completed in avg. %d clock cycles", average/NUM_TV_5);
                    average <= 0;
                    finish_tb;
                end
            end
            endcase
        end
        endcase
  
    end
      
  
    always #(`P/2) clk = ~clk;
  

endmodule
`undef P