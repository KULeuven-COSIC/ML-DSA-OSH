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

// ML-DSA TESTVECTORS ARE OBTAINED FORM: https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json

// Clock settings 
`timescale 1ns / 1ps
`define P 10

// Number of test vectors per parameter set, e.g. xvlog -d NUM_TV_87=3 (0 skips that set)
`ifndef NUM_TV_44
`define NUM_TV_44 15
`endif
`ifndef NUM_TV_65
`define NUM_TV_65 15
`endif
`ifndef NUM_TV_87
`define NUM_TV_87 15
`endif

module tb_verify_top;
    reg clk = 1, rst = 0, start = 0;
    
    reg [2 - 1 : 0] mode = 1; // Verify()
    reg [3 - 1 : 0] sec_lvl = 2; // ML-DSA-44
      
    localparam NUM_TV_2 = `NUM_TV_44;
    localparam NUM_TV_3 = `NUM_TV_65;
    localparam NUM_TV_5 = `NUM_TV_87;
    localparam NUM_TV_23 = (NUM_TV_2 > NUM_TV_3) ? NUM_TV_2 : NUM_TV_3;
    localparam NUM_TV = (NUM_TV_23 > NUM_TV_5) ? NUM_TV_23 : NUM_TV_5; // array depth
    localparam MAX_MLEN_2 = 8192*8; // pad testvectors to this length
    localparam MAX_MLEN_3 = 8192*8; // pad testvectors to this length
    localparam MAX_MLEN_5 = 8192*8; // pad testvectors to this length
    
    localparam MAX_FMTDLEN_2 = MAX_MLEN_2 + 2*8 + `CTX_WIDTH;
    localparam MAX_FMTDLEN_3 = MAX_MLEN_3 + 2*8 + `CTX_WIDTH;
    localparam MAX_FMTDLEN_5 = MAX_MLEN_5 + 2*8 + `CTX_WIDTH;

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
    
    reg [0 : MAX_MLEN_2 - 1]    message_2       [NUM_TV - 1 : 0];
    reg [0 : MAX_FMTDLEN_2 - 1] message_fmtd_2  [NUM_TV - 1 : 0];
    reg [0 : 16 - 1]            mlen_2          [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_2 - 1]   pk_2            [NUM_TV - 1 : 0];
    reg [0 : `CTX_WIDTH - 1]    context_2       [NUM_TV - 1 : 0];
    reg [0 : 8 - 1]             ctxlen_2        [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_2 - 1]  sig_2           [NUM_TV - 1 : 0];
    reg [0 :  1 - 1]            verif_2         [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_2 + 64 - 1] sig_pad_2; // sig_2[c] + 64 bits, so the last (partial) word stays in range
    
    reg [0 : MAX_MLEN_3 - 1]    message_3       [NUM_TV - 1 : 0];
    reg [0 : MAX_FMTDLEN_3 - 1] message_fmtd_3  [NUM_TV - 1 : 0];
    reg [0 : 16 - 1]            mlen_3          [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_3 - 1]   pk_3            [NUM_TV - 1 : 0];
    reg [0 : `CTX_WIDTH - 1]    context_3       [NUM_TV - 1 : 0];
    reg [0 : 8 - 1]             ctxlen_3        [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_3 - 1]  sig_3           [NUM_TV - 1 : 0];
    reg [0 :  1 - 1]            verif_3         [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_3 + 64 - 1] sig_pad_3; // sig_3[c] + 64 bits, so the last (partial) word stays in range
    
    reg [0 : MAX_MLEN_5 - 1]    message_5       [NUM_TV - 1 : 0];
    reg [0 : MAX_FMTDLEN_5 - 1] message_fmtd_5  [NUM_TV - 1 : 0];
    reg [0 : 16 - 1]            mlen_5          [NUM_TV - 1 : 0];
    reg [0 : `PK_WIDTH_5 - 1]   pk_5            [NUM_TV - 1 : 0];
    reg [0 : `CTX_WIDTH - 1]    context_5       [NUM_TV - 1 : 0];
    reg [0 : 8 - 1]             ctxlen_5        [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_5 - 1]  sig_5           [NUM_TV - 1 : 0];
    reg [0 :  1 - 1]            verif_5         [NUM_TV - 1 : 0];
    reg [0 : `SIG_WIDTH_5 + 64 - 1] sig_pad_5; // sig_5[c] + 64 bits, so the last (partial) word stays in range
  
    reg [16 - 1 : 0]    c; // current testvector
    reg [32 - 1 : 0]    ctr; // current data_word 
    reg [16 - 1 : 0]    temp_len;
    
    integer start_time, i, j;
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
        S_SEND_PK_rho   = 4'd2,
        S_SEND_SIG_C    = 4'd3,
        S_SEND_SIG_Z    = 4'd4,
        S_SEND_PK_T1    = 4'd5,
        S_SEND_MLEN     = 4'd6,
        S_SEND_message  = 4'd7,
        S_SEND_SIG_H    = 4'd8,
        S_CHECK_RESULT  = 4'd9,
        S_STOP          = 4'd10;
  
    reg [4 - 1 : 0] state = 0;
  
    initial begin
        // KAT Inputs
        $readmemh("SigVer_message_44.txt", message_2);
        $readmemh("SigVer_message_65.txt", message_3);
        $readmemh("SigVer_message_87.txt", message_5);
        
        $readmemh("SigVer_mlen_44.txt", mlen_2);
        $readmemh("SigVer_mlen_65.txt", mlen_3);
        $readmemh("SigVer_mlen_87.txt", mlen_5);
        
        $readmemh("SigVer_pk_44.txt", pk_2);
        $readmemh("SigVer_pk_65.txt", pk_3);
        $readmemh("SigVer_pk_87.txt", pk_5);
        
        $readmemh("SigVer_ctx_44.txt", context_2);
        $readmemh("SigVer_ctx_65.txt", context_3);
        $readmemh("SigVer_ctx_87.txt", context_5);
        
        $readmemh("SigVer_ctxlen_44.txt", ctxlen_2);
        $readmemh("SigVer_ctxlen_65.txt", ctxlen_3);
        $readmemh("SigVer_ctxlen_87.txt", ctxlen_5);
        
        $readmemh("SigVer_signature_44.txt", sig_2);
        $readmemh("SigVer_signature_65.txt", sig_3);
        $readmemh("SigVer_signature_87.txt", sig_5);
        
        // KAT Outputs
        $readmemb("SigVer_result_44.txt", verif_2);
        $readmemb("SigVer_result_65.txt", verif_3);
        $readmemb("SigVer_result_87.txt", verif_5);
        
        valid_i = 0;
        ready_o = 0;
        data_i  = 0;
        c       = 0;
        ctr     = 0;
        state   = S_INIT;
        start   = 0;
        rst     = 1;
        average = 0;
        
        for (j = 0; j < NUM_TV; j = j + 1) begin
            message_fmtd_2[j] = 0;
            message_fmtd_3[j] = 0;
            message_fmtd_5[j] = 0;
            
            message_fmtd_2[j][0 +: 8] = 8'd0;
            message_fmtd_3[j][0 +: 8] = 8'd0;
            message_fmtd_5[j][0 +: 8] = 8'd0;
            
            message_fmtd_2[j][8 +: 8] = ctxlen_2[j];
            message_fmtd_3[j][8 +: 8] = ctxlen_3[j];
            message_fmtd_5[j][8 +: 8] = ctxlen_5[j];
            
            for (i = 0; i < ctxlen_2[j]; i = i + 1) begin
                message_fmtd_2[j][16 + i*8 +: 8] = context_2[j][(`CTX_BYTES-ctxlen_2[j])*8 + i*8 +: 8];
            end
            for (i = 0; i < ctxlen_3[j]; i = i + 1) begin
                message_fmtd_3[j][16 + i*8 +: 8] = context_3[j][(`CTX_BYTES-ctxlen_3[j])*8 + i*8 +: 8];
            end
            for (i = 0; i < ctxlen_5[j]; i = i + 1) begin
                message_fmtd_5[j][16 + i*8 +: 8] = context_5[j][(`CTX_BYTES-ctxlen_5[j])*8 + i*8 +: 8];
            end
            
            for (i = 0; i < mlen_2[j]; i = i + 1) begin
                message_fmtd_2[j][16 + ctxlen_2[j]*8 + i*8 +: 8] = message_2[j][(MAX_MLEN_2 - mlen_2[j]*8) + i*8 +: 8];
            end
            for (i = 0; i < mlen_3[j]; i = i + 1) begin
                message_fmtd_3[j][16 + ctxlen_3[j]*8 + i*8 +: 8] = message_3[j][(MAX_MLEN_3 - mlen_3[j]*8) + i*8 +: 8];
            end
            for (i = 0; i < mlen_5[j]; i = i + 1) begin
                message_fmtd_5[j][16 + ctxlen_5[j]*8 + i*8 +: 8] = message_5[j][(MAX_MLEN_5 - mlen_5[j]*8) + i*8 +: 8];
            end
        end
    end
  
    always @(posedge clk) begin
        data_i  <= 0;
        valid_i <= 0;
        ready_o <= 0;
        start   <= 0;
        rst     <= 0;
    
        case(sec_lvl)
        2: begin
        
            case(state)
            S_INIT: if (NUM_TV_2 == 0) sec_lvl <= 3; else begin
                start_time <= $time;
                ctr <= ctr + 1;
                rst <= 1;
                
                if (ctr == 0) begin
                    rst <= 1;
                end
                if (ctr == 2) begin
                    ctr <= 0;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                sig_pad_2 = {sig_2[c], 64'd0};
                state <= S_SEND_PK_rho;
            end
            S_SEND_PK_rho: begin
                data_i  <= pk_2[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        state  <= S_SEND_SIG_C;
                        ctr    <= 0;
                        data_i <= sig_2[c][0 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_2[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_C: begin
                data_i  <= sig_2[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `CTILDE_BYTES_2 - 8) begin
                        state  <= S_SEND_SIG_Z;
                        ctr    <= 0;
                        data_i <= sig_2[c][`CTILDE_WIDTH_2 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_2[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_Z: begin
                data_i  <= sig_2[c][`CTILDE_WIDTH_2 + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `z_BYTES_2 - 8) begin
                        state  <= S_SEND_PK_T1;
                        ctr    <= 0;
                        data_i <= pk_2[c][`SKPK_RHO_WIDTH +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_2[c][`CTILDE_WIDTH_2 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_PK_T1: begin
                data_i  <= pk_2[c][`SKPK_RHO_WIDTH + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `PK_t1_BYTES_2 - 8) begin
                        state  <= S_SEND_MLEN;
                        ctr    <= 0;
                        temp_len = mlen_2[c] + {8'd0, ctxlen_2[c]};
                        data_i  <= {48'd0, temp_len};
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_2[c][`SKPK_RHO_WIDTH + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_MLEN: begin
                temp_len = mlen_2[c] + {8'd0, ctxlen_2[c]};
                data_i  <= {48'd0, temp_len};
                valid_i <= 1;
                
                if (ready_i) begin
                    state  <= S_SEND_message;
                    ctr    <= 0;
                    data_i <= message_fmtd_2[c][0 +: 64];
                end
            end
            S_SEND_message: begin
                data_i  <= message_fmtd_2[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if ((ctr * 8 >= mlen_2[c] + 2 + ctxlen_2[c] - 8)  || (mlen_2[c] + ctxlen_2[c] <= 6)) begin
                        state  <= S_SEND_SIG_H;
                        data_i  <= sig_pad_2[`CTILDE_WIDTH_2 + `z_WIDTH_2 +: 64];
                        ctr    <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= message_fmtd_2[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_H: begin
                data_i  <= sig_pad_2[`CTILDE_WIDTH_2 + `z_WIDTH_2 + ctr*64 +: 64];
                valid_i <= 1;
            
                if (ready_i) begin
                    if (ctr * 8 >= `h_BYTES_2 - 8) begin
                        state  <= S_CHECK_RESULT;
                        valid_i <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_pad_2[`CTILDE_WIDTH_2 + `z_WIDTH_2 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_CHECK_RESULT: begin
                ready_o <= 1;
                if (valid_o) begin
                    if (data_o !== verif_2[c]) begin
                        begin $display("[ML-DSA-II.Verify, KAT #%d] WRONG: Expected %h, received %h", c, verif_2[c], data_o); vec_err = 1; end 
                    end 
                    state <= S_STOP;
                end
            end 
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;
                ctr   <= 0;
    
                $display("ML-DSA-II.Verify, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                average <= average + ($time-start_time)/`P;
    
                if (c == NUM_TV_2-1) begin
                    c <= 0;
                    sec_lvl <= 3;
                    $display ("Moving to ML-DSA-III.Verify. ML-DSA-II completed in avg. %d clock cycles", average/(NUM_TV_2-1));
                    average <= 0;
                end       
            end
            endcase
        end
       3: begin
        
           case(state)
           S_INIT: if (NUM_TV_3 == 0) sec_lvl <= 5; else begin
                start_time <= $time;
                ctr <= ctr + 1;
                
                if (ctr == 0) begin
                    rst <= 1;
                end
                if (ctr == 2) begin
                    ctr <= 0;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                sig_pad_3 = {sig_3[c], 64'd0};
                state <= S_SEND_PK_rho;
            end
            S_SEND_PK_rho: begin
                data_i  <= pk_3[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        state  <= S_SEND_SIG_C;
                        ctr    <= 0;
                        data_i <= sig_3[c][0 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_3[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_C: begin
                data_i  <= sig_3[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `CTILDE_BYTES_3 - 8) begin
                        state  <= S_SEND_SIG_Z;
                        ctr    <= 0;
                        data_i <= sig_3[c][`CTILDE_WIDTH_3 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_3[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_Z: begin
                data_i  <= sig_3[c][`CTILDE_WIDTH_3 + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `z_BYTES_3 - 8) begin
                        state  <= S_SEND_PK_T1;
                        ctr    <= 0;
                        data_i <= pk_3[c][`SKPK_RHO_WIDTH +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_3[c][`CTILDE_WIDTH_3 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_PK_T1: begin
                data_i  <= pk_3[c][`SKPK_RHO_WIDTH + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `PK_t1_BYTES_3 - 8) begin
                        state  <= S_SEND_MLEN;
                        ctr    <= 0;
                        temp_len = mlen_3[c] + {8'd0, ctxlen_3[c]};
                        data_i  <= {48'd0, temp_len};
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_3[c][`SKPK_RHO_WIDTH + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_MLEN: begin
                temp_len = mlen_3[c] + {8'd0, ctxlen_3[c]};
                data_i  <= {48'd0, temp_len};
                valid_i <= 1;
                
                if (ready_i) begin
                    state  <= S_SEND_message;
                    ctr    <= 0;
                    data_i <= message_fmtd_3[c][0 +: 64];
                end
            end
            S_SEND_message: begin
                data_i  <= message_fmtd_3[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if ((ctr * 8 >= mlen_3[c] + 2 + ctxlen_3[c] - 8)  || (mlen_3[c] + ctxlen_3[c] <= 6)) begin
                        state  <= S_SEND_SIG_H;
                        data_i  <= sig_pad_3[`CTILDE_WIDTH_3 + `z_WIDTH_3 +: 64];
                        ctr    <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= message_fmtd_3[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_H: begin
                data_i  <= sig_pad_3[`CTILDE_WIDTH_3 + `z_WIDTH_3 + ctr*64 +: 64];
                valid_i <= 1;
            
                if (ready_i) begin
                    if (ctr * 8 >= `h_BYTES_3 - 8) begin
                        state  <= S_CHECK_RESULT;
                        valid_i <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_pad_3[`CTILDE_WIDTH_3 + `z_WIDTH_3 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_CHECK_RESULT: begin
                ready_o <= 1;
                if (valid_o) begin
                    if (data_o !== verif_3[c]) begin
                        begin $display("[ML-DSA-III.Verify, KAT #%d] WRONG: Expected %h, received %h", c, verif_3[c], data_o); vec_err = 1; end 
                    end 
                    state <= S_STOP;
                end
            end 
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;
                ctr   <= 0;
    
                $display("ML-DSA-III.Verify, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                average <= average + ($time-start_time)/`P;
    
                if (c == NUM_TV_3-1) begin
                    c <= 0;
                    sec_lvl <= 5;
                    $display ("Moving to ML-DSA-V.Verify. ML-DSA-III completed in avg. %d clock cycles", average/(NUM_TV_3-1));
                    average <= 0;
                end       
            end
            endcase
        end

        5: begin

            case(state)
            S_INIT: if (NUM_TV_5 == 0) finish_tb; else begin
                start_time <= $time;
                ctr <= ctr + 1;
                
                if (ctr == 0) begin
                    rst <= 1;
                end
                if (ctr == 2) begin
                    ctr <= 0;
                    state <= S_START;
                end
            end
            S_START: begin
                start <= 1;
                sig_pad_5 = {sig_5[c], 64'd0};
                state <= S_SEND_PK_rho;
            end
            S_SEND_PK_rho: begin
                data_i  <= pk_5[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `SKPK_RHO_BYTES - 8) begin
                        state  <= S_SEND_SIG_C;
                        ctr    <= 0;
                        data_i <= sig_5[c][0 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_5[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_C: begin
                data_i  <= sig_5[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `CTILDE_BYTES_5 - 8) begin
                        state  <= S_SEND_SIG_Z;
                        ctr    <= 0;
                        data_i <= sig_5[c][`CTILDE_WIDTH_5 +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_5[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_Z: begin
                data_i  <= sig_5[c][`CTILDE_WIDTH_5 + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `z_BYTES_5 - 8) begin
                        state  <= S_SEND_PK_T1;
                        ctr    <= 0;
                        data_i <= pk_5[c][`SKPK_RHO_WIDTH +: 64];
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_5[c][`CTILDE_WIDTH_5 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_PK_T1: begin
                data_i  <= pk_5[c][`SKPK_RHO_WIDTH + ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if (ctr * 8 == `PK_t1_BYTES_5 - 8) begin
                        state  <= S_SEND_MLEN;
                        ctr    <= 0;
                        temp_len = mlen_5[c] + {8'd0, ctxlen_5[c]};
                        data_i  <= {48'd0, temp_len};
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= pk_5[c][`SKPK_RHO_WIDTH + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_MLEN: begin
                temp_len = mlen_5[c] + {8'd0, ctxlen_5[c]};
                data_i  <= {48'd0, temp_len};
                valid_i <= 1;
                
                if (ready_i) begin
                    state  <= S_SEND_message;
                    ctr    <= 0;
                    data_i <= message_fmtd_5[c][0 +: 64];
                end
            end
            S_SEND_message: begin
                data_i  <= message_fmtd_5[c][ctr*64 +: 64];
                valid_i <= 1;
                
                if (ready_i) begin
                    if ((ctr * 8 >= mlen_5[c] + 2 + ctxlen_5[c] - 8)  || (mlen_5[c] + ctxlen_5[c] <= 6)) begin
                        state  <= S_SEND_SIG_H;
                        data_i  <= sig_pad_5[`CTILDE_WIDTH_5 + `z_WIDTH_5 +: 64];
                        ctr    <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= message_fmtd_5[c][(ctr+1)*64 +: 64];
                    end
                end
            end
            S_SEND_SIG_H: begin
                data_i  <= sig_pad_5[`CTILDE_WIDTH_5 + `z_WIDTH_5 + ctr*64 +: 64];
                valid_i <= 1;
            
                if (ready_i) begin
                    if (ctr * 8 >= `h_BYTES_5 - 8) begin
                        state  <= S_CHECK_RESULT;
                        valid_i <= 0;
                    end else begin
                        ctr    <= ctr + 1;
                        data_i <= sig_pad_5[`CTILDE_WIDTH_5 + `z_WIDTH_5 + (ctr+1)*64 +: 64];
                    end
                end
            end
            S_CHECK_RESULT: begin
                ready_o <= 1;
                if (valid_o) begin
                    if (data_o !== verif_5[c]) begin
                        begin $display("[ML-DSA-V.Verify, KAT #%d] WRONG: Expected %h, received %h", c, verif_5[c], data_o); vec_err = 1; end 
                    end 
                    state <= S_STOP;
                end
            end 
            S_STOP: begin
                if (vec_err) n_fail = n_fail + 1; else n_pass = n_pass + 1;
                vec_err = 0;
                ready_o <= 1;
                c       <= c + 1;
                state <= S_INIT;
                ctr   <= 0;
    
                $display("ML-DSA-V.Verify, KAT #%d completed in %d clock cycles", c, ($time-start_time)/`P);
                average <= average + ($time-start_time)/`P;
    
                if (c == NUM_TV_5-1) begin
                    c <= 0;
                    sec_lvl <= 2;
                    $display ("Testbench done. ML-DSA-V completed in avg. %d clock cycles", average/(NUM_TV_5-1));
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