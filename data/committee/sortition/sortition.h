#ifndef __SORTITION_H__
#define __SORTITION_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif
  uint64_t sortition_binomial_cdf_walk(double n, double p, double ratio, uint64_t money);
#ifdef __cplusplus
}

#endif

#endif
