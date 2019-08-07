#include "sortition.h"
#include <boost/math/distributions/binomial.hpp>

uint64_t sortition_binomial_cdf_walk(double n, double p, double ratio, uint64_t money) {
  boost::math::binomial_distribution<double> dist(n, p);
  for (uint64_t j = 0; j < money; j++) {
    // Get the cdf
    double boundary = cdf(dist, j);

    // Found the correct boundary, break
    if (ratio <= boundary) {
      return j;
    }
  }
  return money;
}
