/*
 * arm/cpu_features.c - feature detection for ARM processors
 *
 * Copyright 2018 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * ARM processors don't have a standard way for unprivileged programs to detect
 * processor features.  But, on Linux we can read the AT_HWCAP and AT_HWCAP2
 * values from /proc/self/auxv.
 *
 * Ideally we'd use the C library function getauxval(), but it's not guaranteed
 * to be available: it was only added to glibc in 2.16, and in Android it was
 * added to API level 18 for ARM and level 21 for AArch64.
 */

#include "../cpu_features_common.h" /* must be included first */
#include "cpu_features.h"

#if ARM_CPU_FEATURES_ENABLED

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define AT_HWCAP	16
#define AT_HWCAP2	26

volatile u32 _cpu_features = 0;

static void scan_auxv(unsigned long *hwcap, unsigned long *hwcap2)
{
	int fd;
	unsigned long auxbuf[32];
	int filled = 0;
	int i;

	fd = open("/proc/self/auxv", O_RDONLY);
	if (fd < 0)
		return;

	for (;;) {
		do {
			int ret = read(fd, &((char *)auxbuf)[filled],
				       sizeof(auxbuf) - filled);
			if (ret <= 0) {
				if (ret < 0 && errno == EINTR)
					continue;
				goto out;
			}
			filled += ret;
		} while (filled < 2 * sizeof(long));

		i = 0;
		do {
			unsigned long type = auxbuf[i];
			unsigned long value = auxbuf[i + 1];

			if (type == AT_HWCAP)
				*hwcap = value;
			else if (type == AT_HWCAP2)
				*hwcap2 = value;
			i += 2;
			filled -= 2 * sizeof(long);
		} while (filled >= 2 * sizeof(long));

		memmove(auxbuf, &auxbuf[i], filled);
	}
out:
	close(fd);
}

static const struct cpu_feature arm_cpu_feature_table[] = {
	{ARM_CPU_FEATURE_NEON,		"neon"},
	{ARM_CPU_FEATURE_PMULL,		"pmull"},
	{ARM_CPU_FEATURE_CRC32,		"crc32"},
};

void setup_cpu_features(void)
{
	u32 features = 0;
	unsigned long hwcap = 0;
	unsigned long hwcap2 = 0;

	scan_auxv(&hwcap, &hwcap2);

#ifdef __arm__
	STATIC_ASSERT(sizeof(long) == 4);
	if (hwcap & (1 << 12))	/* HWCAP_NEON */
		features |= ARM_CPU_FEATURE_NEON;
	if (hwcap2 & (1 << 1))	/* HWCAP2_PMULL */
		features |= ARM_CPU_FEATURE_PMULL;
	if (hwcap2 & (1 << 4))	/* HWCAP2_CRC32 */
		features |= ARM_CPU_FEATURE_CRC32;
#else
	STATIC_ASSERT(sizeof(long) == 8);
	if (hwcap & (1 << 1))	/* HWCAP_ASIMD */
		features |= ARM_CPU_FEATURE_NEON;
	if (hwcap & (1 << 4))	/* HWCAP_PMULL */
		features |= ARM_CPU_FEATURE_PMULL;
	if (hwcap & (1 << 7))	/* HWCAP_CRC32 */
		features |= ARM_CPU_FEATURE_CRC32;
#endif

	disable_cpu_features_for_testing(&features, arm_cpu_feature_table,
					 ARRAY_LEN(arm_cpu_feature_table));

	_cpu_features = features | ARM_CPU_FEATURES_KNOWN;
}

#endif /* ARM_CPU_FEATURES_ENABLED */
