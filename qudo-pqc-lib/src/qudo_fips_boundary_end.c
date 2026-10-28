/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used, noinline, visibility("default")))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
int qudo_fips_module_end(void)
{
    return 0;
}
