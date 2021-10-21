#ifndef LIB_X86_DECOMPRESS_IMPL_H
#define LIB_X86_DECOMPRESS_IMPL_H

#include "cpu_features.h"

/* Include the BMI2-optimized version? */
#undef DISPATCH_BMI2
#if !defined(__BMI2__) && X86_CPU_FEATURES_ENABLED && \
	COMPILER_SUPPORTS_BMI2_TARGET
#  define FUNCNAME	deflate_decompress_bmi2
#  define ATTRIBUTES	__attribute__((target("bmi2")))
#  define DISPATCH	1
#  define DISPATCH_BMI2	1
#  include "../decompress_template.h"
#endif

#ifdef DISPATCH
static inline decompress_func_t
arch_select_decompress_func(void)
{
	u32 features = get_cpu_features();

#ifdef DISPATCH_BMI2
	if (features & X86_CPU_FEATURE_BMI2)
		return deflate_decompress_bmi2;
#endif
	return NULL;
}
#endif /* DISPATCH */

#endif /* LIB_X86_DECOMPRESS_IMPL_H */
