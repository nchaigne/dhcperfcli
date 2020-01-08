#pragma once
/*
 *	ncc_load.h
 */

extern fr_time_t fte_load_start;
extern fr_time_t fte_load_end;
extern fr_time_t fte_load_snapshot;


fr_time_t ncc_load_start_time_set();
fr_time_t ncc_load_end_time_set();

double ncc_load_elapsed_time_snapshot_set();
void ncc_load_time_snapshot_clear();
fr_time_t ncc_fr_time();
fr_time_delta_t ncc_elapsed_fr_time_get(fr_time_t start, fr_time_t end);

fr_time_delta_t ncc_load_elapsed_fr_time_get();
double ncc_load_elapsed_time_get();
