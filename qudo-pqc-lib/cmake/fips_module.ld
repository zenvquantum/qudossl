/*
 * SPDX-License-Identifier: Apache-2.0 AND MIT
 *
 * Supplemental GNU ld script (-Wl,-T,fips_module.ld) that places the
 * integrity-region markers qudo_fips_module_start and qudo_fips_module_end
 * immediately before and after .text. Requires -fno-function-sections.
 *
 * INSERT keeps the script additive to the default linker script. The anchor
 * sections KEEP the sentinels so they are not stripped or folded.
 */

SECTIONS
{
    .qudo_fipsanchor_start : ALIGN(16)
    {
        KEEP(*qudo_fips_boundary_start.c.o(.text .text.*))
    }
}
INSERT BEFORE .text;

SECTIONS
{
    .qudo_fipsanchor_end : ALIGN(16)
    {
        KEEP(*qudo_fips_boundary_end.c.o(.text .text.*))
    }
}
INSERT AFTER .text;
