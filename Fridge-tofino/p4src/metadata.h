#pragma once

//== Metadata variables
header fridge_output_t {
	@padding bit<7> _padding;
        bit<1> query_successful;
        bit<32> delay;
        bit<32> survival_cnt;
}
struct ig_metadata_t {
        fridge_output_t fridge_output;
}
struct eg_metadata_t {
        fridge_output_t fridge_output;
}
