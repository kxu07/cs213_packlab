// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {

  // TODO
  // Validate the header and set configurations based on it
  // Look at unpack-utilities.h to see what the fields of config are
  // Set the is_valid field of config to false if the header is invalid
  // or input_len (length of the input_data) is shorter than expected
  
	//make sure that the input_len is a valid length
  config->is_valid = false;
	if (input_len < 20) {
    return;
	} 

  // check magic and version
  if (!((input_data[0] == 0x02) && (input_data[1] == 0x13))) {
    return;
  } 
  if (!(input_data[2]==0x03)) {
    return;
  }

  // check all flags 
  int req_length = 20;
  uint8_t flags = input_data[3];
  uint8_t mask = 1 << 2; // 4 = 0000 0100
  config->should_float3 = mask & flags;
  mask = mask << 1;
  config->should_float = mask & flags;
  mask = mask << 1;
  config->should_continue = mask & flags;
  mask = mask << 1;
  config->is_checksummed = mask & flags;
  mask = mask << 1;
  if (config->is_checksummed) { 
    req_length += 2;
  }
  config->is_encrypted = mask & flags;
  mask = mask << 1;
  config->is_compressed = mask & flags;
  if (config->is_compressed) {
    req_length += 16;
  }
  // ensure right length
  if (input_len < req_length) {
    return;
  }

  // get original length and compressed length
  uint64_t orig_length = 0;
  for (int i=4; i<12; i++) {
    orig_length |= ((uint64_t) input_data[i] << 8*(i-4));
  }
  config->orig_data_size = orig_length;
  uint64_t comp_length = 0;
  for (int i=12; i<20; i++) {
    comp_length |= ((uint64_t) input_data[i] << 8*(i-12));
  }
  config->data_size = comp_length;

  int checksum_start = 20;
  // get compression dictionary
  if (config->is_compressed) {
    memcpy(config->dictionary_data, &input_data[20], 16*sizeof(uint8_t));
    checksum_start += 16;
  }

  // get checksum value
  if (config->is_checksummed) {
    config->checksum_value = (input_data[checksum_start] << 8) + input_data[checksum_start+1];
  }
  config->is_valid = true;
  config->header_len = req_length;
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {

  // TODO
  // Calculate a checksum over input_data
  // Return the checksum value
  uint16_t checksum = 0;
  for (int i=0; i< input_len; i++) {
    checksum += input_data[i];
  }
  return checksum;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state
  uint16_t msb = (oldstate & 1) ^ ((oldstate & (1 << 6)) >> 6) 
                                ^ ((oldstate & (1 << 9)) >> 9)
                                ^ ((oldstate & (1<<13))>>13);
  oldstate = oldstate >> 1;

  oldstate = oldstate + (msb << 15);
  return oldstate;
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in little-endian order
  // Beware: input_data may be an odd number of bytes
  uint16_t lfsr_state = lfsr_step(encryption_key);
  if (input_len > output_len) {
    printf("Output size too small for decrypt_data\n");
  }
  for (int i=0; i<input_len-1; i+=2) {
    output_data[i] = lfsr_state ^ input_data[i];
    output_data[i+1] = (lfsr_state>>8) ^ input_data[i+1];
    lfsr_state = lfsr_step(lfsr_state);
    
  }
  if (input_len%2 == 1) {
    //odd byte 
    output_data[input_len-1] = lfsr_state^input_data[input_len-1];
  }
  // should be fine -> areas of anxiety (indexing?)

}

size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data
  if (output_len < input_len) {
    printf("Output len is too small for decompress_data\n");
    return -1;
  }
  int output_index = 0;
  for (int i=0;i<input_len;i++) {
    if (output_index >= output_len) {
      printf("Output index too large, overflow\n");
      return -1;
    }
    if (input_data[i] != 0x07) {
      output_data[output_index] = input_data[i];
      output_index++;
    } else {
      if ((i==input_len-1)|| (input_data[i+1]==0)){
        // escape byte: either it's the last byte of the file or its 0x07 00
        output_data[output_index] = 0x07;
        output_index++;
      } else {
        // actual compressed value
        uint8_t next_byte = input_data[i+1];
        uint8_t dict_index = next_byte & 15;
        uint8_t repeat = next_byte >> 4;
        for (int j=0;j<repeat;j++) {
          if (output_index >= output_len) {
            printf("Output index too large, overflow\n");
            return -1;
          }
          output_data[output_index] = dictionary_data[dict_index];
          output_index++;
        }
      }
      i++;
    }
  }
  return output_index;
}

void join_float_array(uint8_t* input_signfrac, size_t input_len_bytes_signfrac,
                      uint8_t* input_exp, size_t input_len_bytes_exp,
                      uint8_t* output_data, size_t output_len_bytes) {

  // TODO
  // Combine two streams of bytes, one with signfrac data and one with exp data,
  // into one output stream of floating point data
  // Output bytes are in little-endian order
  size_t total_len = input_len_bytes_signfrac + input_len_bytes_exp;
  if (output_len_bytes < total_len) {
    printf("Output length too small for join_float_array\n");
    return;
  }
  size_t signfrac_index = 0;
  size_t exp_index = 0;
  size_t output_index = 0;
  while (true) {
    //Byte 0 of output
    output_data[output_index] = input_signfrac[signfrac_index];
    //Byte 1 of output
    output_data[output_index+1] = input_signfrac[signfrac_index+1];
    //Byte 2 of output
    uint8_t byte2 = input_signfrac[signfrac_index+2] & 0x7F; //lower 7 bits from signfrac
    byte2 |= (input_exp[exp_index] & 1) << 7; //lowest bit from exp
    output_data[output_index+2] = byte2;
    //Byte 3 of output
    uint8_t byte3 = input_exp[exp_index] >> 1; //upper 7 bits from exp
    byte3 |= (input_signfrac[signfrac_index+2]) & 0x80; //add sign bit from signfrac
    output_data[output_index+3] = byte3;
    signfrac_index += 3;
    exp_index++;
    output_index += 4;
    if (signfrac_index >= input_len_bytes_signfrac || exp_index >= input_len_bytes_exp) {
      break;
    }
  }
}
/* End of mandatory implementation. */

/* Extra credit */
void join_float_array_three_stream(uint8_t* input_frac,
                                   size_t   input_len_bytes_frac,
                                   uint8_t* input_exp,
                                   size_t   input_len_bytes_exp,
                                   uint8_t* input_sign,
                                   size_t   input_len_bytes_sign,
                                   uint8_t* output_data,
                                   size_t   output_len_bytes) {

  // TODO
  // Combine three streams of bytes, one with frac data, one with exp data,
  // and one with sign data, into one output stream of floating point data
  // Output bytes are in little-endian order
  size_t num_floats = input_len_bytes_exp; //number of floats is determined by exp length

  for (size_t i = 0; i < num_floats; i++) {
    //Extract mantissa
    uint32_t mantissa = 0;
    size_t mantissa_current_byte = i * 23 / 8;
    size_t mantissa_starting_bit = i * 23 % 8;
    uint32_t bitdiff = 8 - mantissa_starting_bit;
    // If mantissa starts in middle of byte
    if (mantissa_starting_bit > 0) {
      uint32_t mask = 0xFF >> mantissa_starting_bit;
      mantissa |= input_frac[mantissa_current_byte] & mask;
      mantissa_current_byte++;
    }

    // Read guaranteed two full bytes
    for (int j = 0; j < 2; j++) {
      mantissa |= input_frac[mantissa_current_byte] << (j * 8 + bitdiff);
      mantissa_current_byte++;
    }

    // Read remaining bits if any
    int remaining_bits = 23 - 16 - bitdiff;
    if (remaining_bits) {
      mantissa |= input_frac[mantissa_current_byte] >> (8 - remaining_bits) << (16 + bitdiff);
    }

    // Write to output
    // Byte 0
    output_data[i] = mantissa & 0xFF;
    // Byte 1
    output_data[i + 1] = (mantissa >> 8) & 0xFF;
    // Byte 2
    output_data[i + 2] = mantissa >> 16;
    output_data[i + 2] |= (input_exp[i] & 1) << 7;
    // Byte 3
    output_data[i + 3] = input_exp[i] >> 1;
    size_t sign_byte = i / 8;
    int sign_bit = i % 8;
    output_data[i + 3] |= ((input_sign[sign_byte] >> sign_bit) & 1) << 7;
  }
}

